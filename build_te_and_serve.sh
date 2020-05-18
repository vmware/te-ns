mkdir -p $PATH_TO_TE/te_dp/bin#!/bin/bash
set -e

if [[ $# -ne 3 ]] ; then
    echo 'Pass <repo-name-to-build-the-docker-image> <machine-IP> and <path to traffic engine> to save it!'
    exit 1
fi

GREEN='\033[0;32m'
NC='\033[0m'
USER=root
PASSWORD=avi123
TARGET=/usr/share/nginx/html/$1/
IP=$2
PATH_TO_TE=$3
PWD=$(pwd)

#BUILD AND SAVE TEDP DOCKER
docker container prune -f && docker image prune -f
docker build -t tedp_bin:v2.0 -f $PATH_TO_TE/te/tedp_docker/tedp_bin_builder.dockerfile $PATH_TO_TE/
docker build -t tedp:v2.0 -f $PATH_TO_TE/te/tedp_docker/Dockerfile $PATH_TO_TE/
docker save -o $PATH_TO_TE/te/tedp_docker.tar tedp:v2.0
IMAGE_ID_TEDP=`docker images -q -a tedp:v2.0`
echo -e "${GREEN}Perfomed a Docker save of TE_DP Docker ${NC}"

#BUILD AND SAVE TE DOCKER
docker build -t te:v2.0 --build-arg IMAGE_ID=$IMAGE_ID_TEDP -f $PATH_TO_TE/te/te_docker/Dockerfile $PATH_TO_TE/te/
docker save -o $PATH_TO_TE/te/te_docker.tar te:v2.0
IMAGE_ID_TE=`docker images -q -a te:v2.0`
echo -e "${GREEN}Performed a Docker save of TE Docker ${NC}"

#COPY TE DOCKER TO /etc/nginx/html of maintained REPO
sshpass -p $PASSWORD ssh -o "StrictHostKeyChecking no" -t $USER@$IP "mkdir -p ${TARGET}; mkdir -p ${TARGET}static"
sshpass -p $PASSWORD scp -o "StrictHostKeyChecking no" $PATH_TO_TE/te/te_docker.tar $USER@$IP:$TARGET
sshpass -p $PASSWORD scp -o "StrictHostKeyChecking no" $PATH_TO_TE/te/TE_WRAP.py $USER@$IP:$TARGET
sshpass -p $PASSWORD scp -o "StrictHostKeyChecking no" $PATH_TO_TE/te/GET_AND_RUN_DOCKER_IMAGE.py $USER@$IP:$TARGET
sshpass -p $PASSWORD scp -o "StrictHostKeyChecking no" $PATH_TO_TE/te/TE_SWAGGER.py $USER@$IP:$TARGET
sshpass -p $PASSWORD scp -o "StrictHostKeyChecking no" $PATH_TO_TE/te/setup_te_swagger.json $USER@$IP:$TARGET/static/
echo -e "${GREEN}Saved the TE docker tar to ${TARGET} in machine ${IP} ${NC}"

sshpass -p $PASSWORD ssh -o "StrictHostKeyChecking no" -t $USER@$IP "md5sum ${TARGET}/te_docker.tar > ${TARGET}/check.sum"
sshpass -p $PASSWORD ssh -o "StrictHostKeyChecking no" -t $USER@$IP "echo ${IMAGE_ID_TE} > ${TARGET}/image.id; chmod -R 755 ${TARGET}"
echo -e "${GREEN}Computed and save the check.sum and contents of ${TARGET} are ${NC}"
sshpass -p $PASSWORD ssh -o "StrictHostKeyChecking no" -t $USER@$IP "ls -l ${TARGET}"
