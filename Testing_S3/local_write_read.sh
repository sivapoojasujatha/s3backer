#!/bin/bash

runthis(){
    ## print the command to the logfile
    echo "$@"
    ## run the command and redirect it's error output
    ## to the logfile
    eval "$@"
}

printf "\n\033[1;34m******************************Start local_write_read.sh script**********************************\033[0m\n"

printf "\033[1;34mThis script writes 10 blocks of BS=4K to local store. Reads back the written data and compares if done correctly.\033[0m\n"
printf "\033[1;34mAlso tests reading some blocks from cloud store and compares if done correctly.\033[0m\n"

printf "\n\033[1;34mclean up cloud store bucket first\033[0m\n"
runthis "../cloudbacker --accessFile=/home/build/.s3backer_passwd_s3 --size=10M --blockSize=4K s3://sujathas3b1 --erase --force"

printf "\n\033[1;34mmount and write blocks to cloudstore\033[0m\n"
runthis "../cloudbacker --accessFile=/home/build/.s3backer_passwd_s3 --size=10M --blockSize=4K s3://sujathas3b1 /mnt/source/ --listBlocks"

printf "\n\033[1;34mwrite blocks to cloudstore\033[0m\n"
runthis "dd if=writeTocloud.txt of=/mnt/source/file bs=4096 count=10"

printf "\n\033[1;34munmount file system\033[0m\n"
runthis "umount /mnt/source"

printf "\n\033[1;34mwaiting for cloudbacker to exit\033[0m\n"
ps axho comm| grep cloudbacker > /dev/null
result=$?
while [ "${result}" -eq "0" ]; do
      sleep 1
      ps axho comm| grep cloudbacker > /dev/null
      result=$?
done
printf "\n\033[1;34munmount done\033[0m\n"

printf "\n\033[1;34mmount and write blocks to localstore\033[0m\n"
runthis "../cloudbacker --accessFile=/home/build/.s3backer_passwd_s3 --size=10M --blockSize=4K s3://sujathas3b1 /mnt/source/ --listBlocks --localStore=/dev/loop0"

printf "\n\033[1;34mwrite blocks to localstore\033[0m\n"
runthis "dd if=writeTolocal.txt of=/mnt/source/file bs=4096 count=10"

printf "\n\033[1;34munmount file system\033[0m\n"
runthis "umount /mnt/source"

printf "\n\033[1;34mwaiting for cloudbacker to exit\033[0m\n"
ps axho comm| grep cloudbacker > /dev/null
result=$?
while [ "${result}" -eq "0" ]; do
      sleep 1
      ps axho comm| grep cloudbacker > /dev/null
      result=$?
done
printf "\n\033[1;34munmount done\033[0m\n"


printf "\n\033[1;34mremount file system\033[0m\n"
runthis "../cloudbacker --accessFile=/home/build/.s3backer_passwd_s3 --size=10M --blockSize=4K s3://sujathas3b1 /mnt/source/ --listBlocks --localStore=/dev/loop0"

printf "\n\033[1;34mread blocks written earlier to localstore\033[0m\n"
runthis "dd of=readFromlocal.txt if=/mnt/source/file bs=4096 count=10"

printf "\n\033[1;34mcompare writeTolocal.txt and readFromlocal.txt to confirm if read write worked correctly.\033[0m\n"
if diff writeTolocal.txt readFromlocal.txt >/dev/null ; then
  echo -e "both files are same"
else
  echo -e "files are different"
fi

printf "\n\033[1;34munmount file system\033[0m\n"
runthis "umount /mnt/source"

printf "\033[1;34mwaiting for cloudbacker to exit\033[0m\n"
ps axho comm| grep cloudbacker > /dev/null
result=$?
while [ "${result}" -eq "0" ]; do
      sleep 1
      ps axho comm| grep cloudbacker > /dev/null
      result=$?
done
printf "\n\033[1;34munmount done\033[0m\n"

printf "\033[1;34mNow mount with localstore and read from cloud store\033[0m\n"

printf "\n\033[1;34mempty the block device\033[0m\n"
runthis "dd if=/dev/zero of=/dev/loop0 bs=4096 count=7680"

printf "\033[1;34mNow mount with localstore and read from cloud store\033[0m\n"
runthis "../cloudbacker --accessFile=/home/build/.s3backer_passwd_s3 --size=10M --blockSize=4K s3://sujathas3b1 /mnt/source/ --listBlocks --localStore=/dev/loop0"

printf "\n\033[1;34mread blocks - as block device is empty, it should read from cloudstore\033[0m\n"
runthis "dd of=readFromlocalcloud.txt if=/mnt/source/file bs=4096 count=10"

printf "\n\033[1;34mcompare writeTocloud.txt and readFromlocalcloud.txt to confirm if read write worked correctly.\033[0m\n"
#since we are reading all blocks from cloud, compare cloud blocks with read blocks
if diff writeTocloud.txt readFromlocalcloud.txt >/dev/null ; then
  printf "\n\033[1;32mboth files are same\033[0m\n"
  printf "\n\033[1;32m****************** PASS ********************\033[0m\n"
else
  printf "\n\033[1;31mfiles are different\033[0m\n"
  printf "\n\033[1;31m****************** FAIL ********************\033[0m\n"
fi

printf "\n\033[1;34munmount file system\033[0m\n"
runthis "umount /mnt/source"

printf "\033[1;34mwaiting for cloudbacker to exit\033[0m\n"
ps axho comm| grep cloudbacker > /dev/null
result=$?
while [ "${result}" -eq "0" ]; do
      sleep 1
      ps axho comm| grep cloudbacker > /dev/null
      result=$?
done
printf "\n\033[1;34munmount done\033[0m\n"

printf "\n\033[1;31mNOTE :: cleanup read log files using command 'rm -f readFrom*.txt', if required\033[0m\n"

printf "\n\033[1;34m************************************End local_write_read.sh script*******************************************\033[0m\n"

