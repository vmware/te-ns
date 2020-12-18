How to package TE-NS
====================
* TE-NS works as a docker container.
* The packaging is done in such a fashion that the TE-NS Controller docker image
  carries the datapath docker image wihin it.
* This TE-NS Controller image needs hosted as a downloadable file in a HTTP server. (nginx / apache)
* The build and deploy can be done in one shot (refer to 1A) or in 2 steps of package and
  deploying (refer to 2A and 2B)
* For the build process 1A and 2A the following are the pre-requisites
  - A community edition of docker installed (preferrably 18.06+)
  - Active internet connection to do apt install and downloads of packages
* Please note that the 1st build might be slow but consequent builds will be faster

1A) How to build and host TE-NS repo in a HTTP Server in 1 shot
===============================================================
* Pre-requisites include:
  - python3
  - nginx / apache2 installed and running
  - docker
  - pip3 installed paramiko, flask-swagger-ui, scp
```
./build_te_and_serve.sh <REPO_PATH> <REPO_NAME> <REPO_IP> <PATH TO TRAFFIC ENGINE> <PASSWORD_OF_ROOT_USER> <SWAGGER_PORT>(optional -- default 4000)
./build_te_and_serve.sh /usr/share/nginx/html/ te-ns-repo 127.0.0.1 . avi123 4000
```

2A) How to build a TE-NS tarball for external deploy
====================================================
* The below step builds the TE-NS repo and tarballs other files as well needed to setup and use TE-NS

```
./build_te_repo_tar.sh $PATH_TO_TE_NS_GIT_REPO
Eg:
./build_te_repo_tar.sh .
```

* Post the execution of above command, upon success, traffic_engine.tar.gz would be generated

2B) How to deploy from the tarball from 2A
==========================================
* To deploy traffic_engine.tar.gz generated in any other host
* Pre-requisites include:
  - python3
  - nginx / apache2 installed and running
  - docker
  - pip3 installed paramiko, flask-swagger-ui, scp
* scp the traffic_engine.tar.gz to the target host

```
./deploy_te_repo.sh <PATH TO NGINX ROOT> <REPO NAME> <REPO_IP> <PATH TO traffic_engine.tar.gz> <SWAGGER_PORT>(optional -- default 4000)
Eg:
./deploy_te_repo.sh /usr/share/nginx/html/ te-ns-repo 127.0.0.1 ./traffic_engine.tar.gz 4000
```

* To check if the repo is up and working:
```
systemctl status te-swagger@<REPO NAME>.service
Eg:
systemctl status systemctl status te-swagger@te-ns-repo.service
```
