#!/bin/bash


runthis(){
    ## print the command to the logfile
    echo "$@" 
    ## run the command and redirect it's error output
    ## to the logfile
    eval "$@"  
}
printf "\033[1;34mThis is red text\033[0m\n"
echo -e "*****Start cloud_write_read.sh script*****"
echo -e "*****This script writes 10 blocks of BS=4K to cloud store. Reads back the written data and compares if done correctly.*****"

echo -e "*****clean up cloud store bucket first*****"
runthis "../cloudbacker --accessFile=/home/build/.s3backer_passwd_gcs --size=10M --blockSize=4K gs://gcs-nearline-sujatha --erase --force"

ps axho comm| grep cloudbacker > /dev/null
result=$?
while [ "${result}" -eq "0" ]; do 
      sleep 1
      ps axho comm| grep cloudbacker > /dev/null
      result=$?
done




