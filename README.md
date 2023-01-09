# About

This little Docker container will gets vessel position using AIS and sends it to a [Traccar](https://www.traccar.org/) server.  
In a multi-user environment it allows users to configure devices without involving the administrator.
## How to

### Docker

Clone this repo and then add this to your `docker-compose.yml` file:

```yaml
  ais2traccar:
    build: https://github.com/traccartools/ais2traccar.git
    container_name: ais2traccar  # optional
    environment:
      - "TRACCAR_HOST=https://traccar.example.com"  # optional, defaults to http://traccar:8082
      - "TRACCAR_USER=user" # optional but recommended
      - "TRACCAR_PASSWORD=pass" # optional but recommended
      - "TRACCAR_KEYWORD=ais_in" # optional, defaults to ais
      - "TRACCAR_INTERVAL=120" # optional, defaults to 60
      - "TRACCAR_OSMAND=http://traccar.example.com:5055"  # optional, defaults to http://[TRACCAR_HOST]:5055
      - "AIS_INTERVAL=120" # optional, defaults to 60
      - "LOG_LEVEL=DEBUG"  # optional, defaults to INFO
    restart: unless-stopped
  ```
  
  * `TRACCAR_HOST` is your Traccar server's URI/URL. If run in the same docker-compose stack, name your Traccar service `traccar` and omit this env var.
  * `TRACCAR_USER` is your Traccar server's username. It should be the admin or an admin user with readonly permission.
  * `TRACCAR_PASSWORD` is your Traccar server's password.
  * `TRACCAR_KEYWORD` is the attribute name to be set in your device.
  * `TRACCAR_INTERVAL` is the polling time (in seconds) of the traccar devices.
  * `TRACCAR_OSMAND` is your Traccar server's Osmand protocol URL
  * `AIS_INTERVAL` is the polling time (in seconds) of the AIS vessels


### Traccar

Create a device with arbitrary identifier.
Add a device attribute with name = `TRACCAR_KEYWORD` and value = MMSI you intend to track.
Wait `TRACCAR_INTERVAL` seconds in order for the changes takes effect.

