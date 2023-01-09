#!/usr/bin/env python3

import logging
import os
import signal
import requests

from apscheduler.schedulers.background import BlockingScheduler, BackgroundScheduler
from datetime import datetime
from urllib.parse import urlparse, urlunparse
from requests.auth import HTTPBasicAuth
import json
import re

from aisexplorer.AIS import AIS

DEFAULT_TRACCAR_HOST = 'http://traccar:8082'
DEFAULT_TRACCAR_KEYWORD = 'ais'
DEFAULT_TRACCAR_INTERVAL = 60
DEFAULT_AIS_INTERVAL = 60

LOGGER = logging.getLogger(__name__)

class AIS2Traccar():
    def __init__(self, conf: dict):
        # Initialize the class.
        super().__init__()
        
        self.TraccarHost = conf.get("TraccarHost")
        self.TraccarUser = conf.get("TraccarUser")
        self.TraccarPassword = conf.get("TraccarPassword")
        self.TraccarKeyword = conf.get("TraccarKeyword")
        self.TraccarOsmand = conf.get("TraccarOsmand")
        self.TraccarInterval = conf.get("TraccarInterval")
        self.AISInterval = conf.get("AISInterval")

        self.scheduler = BackgroundScheduler()
        self.scheduler.start()

        self.historydict = {}
        self.filterdict = {}

    
    def poll(self):
        page = requests.get(self.TraccarHost + "/api/devices?all=true", auth = HTTPBasicAuth(self.TraccarUser, self.TraccarPassword))
        if page.status_code != 200:
            LOGGER.info("Traccar auth failed")
            return

        filterdict={}
        for j in json.loads(page.content):
            # print(json.dumps(j, indent=2))
            if not j["disabled"]:
                attributes = j["attributes"]

                for att, value in attributes.items():
                    if re.search("^" + self.TraccarKeyword + "[0-9]{0,1}$", att.lower()):
                        mmsi = value.upper().strip()
                        if re.search("^[0-9]{9}$", mmsi):
                            unid = j["uniqueId"]
                            filterdict[mmsi] = filterdict.get(mmsi, []) + [unid]

        self.filterdict = filterdict
        LOGGER.debug(f"Attributes: {filterdict}")

        filterjobs =[x.id for x in self.scheduler.get_jobs()]
        LOGGER.debug(f"Jobs: {filterjobs}")

        for filter in filterjobs:
            #delete old jobs
            if not filter in filterdict:
                LOGGER.debug(f"Job removed: {filter}")
                self.scheduler.remove_job(filter)

        for filter in filterdict:
            # check if it's running
            if not filter in filterjobs:
                LOGGER.debug(f"Job added: {filter}")
                self.scheduler.add_job(self.getais, 'interval', args=[filter], next_run_time=datetime.now(), seconds=self.AISInterval, name=filter, id=filter)

    


    def getais(self, *args):
        filter = args[0]
        LOGGER.debug("Getting AIS Positions of %s" % filter)

        # getting position
        msg = AIS().get_location(filter)[0]

        lpos = msg['LAST_POS']

        #if timestamp is too old skip it
        if (datetime.now() - datetime.fromtimestamp(lpos)).total_seconds() > self.AISInterval * 5:
            logging.debug(f"Old timestamp: {filter} {lpos}")
            return

        #if timestamp is duplicated skip it
        if lpos == self.historydict.get(filter):
            logging.debug(f"Duplicate timestamp: {filter} {lpos}")
            return

        self.historydict[filter] = lpos

        lat = msg['LAT']
        lon = msg['LON']
        speed = msg['SPEED']
        bearing = msg['COURSE'] or "0"

        #metric conversion
        speed = str(float(speed) * 1.852)

        query_string = f"&lat={lat}&lon={lon}&speed={speed}&bearing={bearing}&timestamp={lpos}"

        # extra attributes
        for attr in ['MMSI', 'CALLSIGN', 'SHIPNAME', 'AREA_NAME', 'AREA_CODE', 'CURRENT_PORT', 'CURRENT_PORT_COUNTRY', 'NEXT_PORT_NAME', "NEXT_PORT_COUNTRY"]:
            if attr in msg:
                query_string += f"&AIS_{attr.lower()}={msg[attr]}"

        dev_ids = self.filterdict.get(filter)
        for dev_id in dev_ids:
            query_fullstring = f"id={dev_id}" + query_string
            try:
                self.tx_to_traccar(query_fullstring)
            except ValueError:
                logging.warning(f"id={dev_id}")


    def tx_to_traccar(self, query: str):
        # Send position report to Traccar server
        LOGGER.debug(f"tx_to_traccar({query})")
        url = f"{self.TraccarOsmand}/?{query}"
        try:
            post = requests.post(url)
            logging.debug(f"POST {post.status_code} {post.reason} - {post.content.decode()}")
            if post.status_code == 400:
                logging.warning(
                    f"{post.status_code}: {post.reason}. Please create device with matching identifier on Traccar server.")
                raise ValueError(400)
            elif post.status_code > 299:
                logging.error(f"{post.status_code} {post.reason} - {post.content.decode()}")
        except OSError:
            logging.exception(f"Error sending to {url}")







if __name__ == '__main__':
    log_level = os.environ.get("LOG_LEVEL", "INFO")

    logging.basicConfig(level=log_level)


    def sig_handler(sig_num, frame):
        logging.debug(f"Caught signal {sig_num}: {frame}")
        logging.info("Exiting program.")
        exit(0)

    signal.signal(signal.SIGTERM, sig_handler)
    signal.signal(signal.SIGINT, sig_handler)

    def OsmandURL(url):
        u = urlparse(url)
        u = u._replace(scheme="http", netloc=u.hostname+":5055", path = "")
        return(urlunparse(u))

    config = {}
    config["TraccarHost"] = os.environ.get("TRACCAR_HOST", DEFAULT_TRACCAR_HOST)
    config["TraccarUser"] = os.environ.get("TRACCAR_USER", "")
    config["TraccarPassword"] = os.environ.get("TRACCAR_PASSWORD", "")
    config["TraccarKeyword"] = os.environ.get("TRACCAR_KEYWORD", DEFAULT_TRACCAR_KEYWORD)
    config["TraccarInterval"] = int(os.environ.get("TRACCAR_INTERVAL", DEFAULT_TRACCAR_INTERVAL))
    config["AISInterval"] = int(os.environ.get("AIS_INTERVAL", DEFAULT_AIS_INTERVAL))
    config["TraccarOsmand"] = os.environ.get("TRACCAR_OSMAND", OsmandURL(config["TraccarHost"]))
    
    A2T = AIS2Traccar(config)

    logging.getLogger('apscheduler.executors.default').setLevel(logging.WARNING)
    sched = BlockingScheduler()
    sched.add_job(A2T.poll, 'interval', next_run_time=datetime.now(), seconds=config["TraccarInterval"])
    sched.start()



