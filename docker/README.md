# keycloak-mysql-docker-sample

This is an example of Keycloak 12.0.1 with MySQL 8.0.
I had some troubles in building them, so I decided to left this sample.

## Environment

* Keycloak 12.0.1
* MySQL 8.0.22
* Docker for Mac

## How to use

```
$ docker-compose up
```

## for Apple Silicon Users

When I used the default image of Keycloak in my M1 MacBook Pro 2020, the image seems not to start correctly,
and I found the image is built for the x64_86 environment.
I rebuilt the image with my M1 MacBook, and I succeeded in using it.

You can find which arcitecture the image is built for, with the following command.

```
$ docker image inspect jboss/keycloak:12.0.1
```

The way of building `arm64` image is the following.

```
$ git clone git@github.com:keycloak/keycloak-containers.git
$ cd keycloak-containers
$ git checkout 12.0.1
$ cd servers
$ docker build -t jboss/keycloak:12.0.1 .
```

## for Timeout Issues

There are a couple of timeout issues related to migration, and you will fail without setting them longer when you start the image for the first time.

The first one is the `WFLYCTL0348` error, and the `jboss.as.management.blocking.timeout` option affects it.

```
keycloak_1       | ERROR [org.jboss.as.controller.management-operation] (Controller Boot Thread) WFLYCTL0348: Timeout after [300] seconds waiting for service container stability. Operation will roll back. Step that first updated the service container was 'add' at address '[
keycloak_1       |     ("core-service" => "management"),
keycloak_1       |     ("management-interface" => "http-interface")
keycloak_1       | ]'

```

The second is the transaction timeout like the following, and you can avoid it by making the transactions timeout longer.

```
keycloak_1       | WARN  [com.arjuna.ats.arjuna] (Transaction Reaper) ARJUNA012117: TransactionReaper::check timeout for TX 0:ffffac150003:1d53c5e9:5ff0d6f2:14 in state  RUN
keycloak_1       | WARN  [com.arjuna.ats.arjuna] (Transaction Reaper Worker 0) ARJUNA012095: Abort of action id 0:ffffac150003:1d53c5e9:5ff0d6f2:14 invoked while multiple threads active within it.
keycloak_1       | WARN  [com.arjuna.ats.arjuna] (Transaction Reaper Worker 0) ARJUNA012381: Action id 0:ffffac150003:1d53c5e9:5ff0d6f2:14 completed with multiple threads - thread ServerService Thread Pool -- 71 was in progress with java.base@11.0.9.1/java.net.SocketInputStream.socketRead0(Native Method)
```

As the Keycloak docker image automatically starts scripts which are placed in `/opt/jboss/startup-scripts` in the start-up process, we can utilize it. This mechanism are described in [`server/tools/autorun.sh`](https://github.com/keycloak/keycloak-containers/blob/master/server/tools/autorun.sh) in the [`keycloak-containers`](https://github.com/keycloak/keycloak-containers) repository.
This sample loads `change-default-timeout.cli`.

## References

* [WFLYCTL0348: TimeoutException while running Keycloak in a Docker container with an external database (MariaDB)](https://serviceorientedarchitect.com/wflyctl0348-timeoutexception-while-running-keycloak-in-a-docker-container-with-an-external-database-mariadb/)
* [Keycloak Timeout Issue](https://keycloak.discourse.group/t/keycloak-timeout-issue/2309)
