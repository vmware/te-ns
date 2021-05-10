TE-NS Packaging
===============
* TE-NS works as a docker container.
* The packaging is done in such a fashion that the TE-NS Controller docker image carries the datapath docker image wihin it.
* Pre-requisites to build the image
    - A community edition of docker installed (preferrably 18.06+)
    - Active internet connection to do apt install and downloads of packages
* Please note that the 1st build might be slow but consequent builds will be faster

How to build TE-NS image
========================
* Clone the github repository from https://github.com/vmware/te-ns
```
git clone https://github.com/vmware/te-ns.git
```
* Change directory 
```
cd te-ns
```
* Build the image
```
[sudo] ./build_te.sh
```

How to setup a local docker repository (Skip if registry is already setup)
==========================================================================
* Setup a docker repository and make the image downloadable across all hosts in the local n/w
```
export DOCKER_REGISTRY_PORT=6666
[sudo] docker run -d -p $DOCKER_REGISTRY_PORT:$DOCKER_REGISTRY_PORT --restart=always --name registry -v /data/docker:/var/lib/registry -e REGISTRY_HTTP_ADDR=0.0.0.0:$DOCKER_REGISTRY_PORT registry:2
```

How to publish the built TE-NS image to a local docker registry
===============================================================
* Publish the built image to the local registry
```
export DOCKER_REGISTRY_IP=127.0.0.1
export DOCKER_REGISTRY_PORT=6666
export IMAGE_NAME=te:v2.0
./publish_te.sh $DOCKER_REGISTRY_IP:$DOCKER_REGISTRY_PORT/$IMAGE_NAME
```

How to get UI for setting up TE-NS container
============================================
```
[sudo] apt install python3 python3-pip
pip3 install flask flask_swagger_ui paramiko flask-swagger-ui scp
export FLASK_PORT=4000
[sudo] ./setup_te_setup_dashboard.sh $FLASK_PORT
```

For configuring insecure registries on the client, do the following:
============================================

* Set the following flag in the /etc/docker/daemon.json file on the client:
```
{
    "insecure-registries": ["DOCKER_REGISTRY_IP:DOCKER_REGISTRY_PORT"]
}
```

* Restart Docker
```
$ sudo systemctl restart docker
```

To pull te image from the newly created registry:
============================================
```
docker pull DOCKER_REGISTRY_IP:DOCKER_REGISTRY_PORT/te:v2.0
```
