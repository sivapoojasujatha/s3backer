#!/bin/bash

runthis(){
    ## print the command to the logfile
    echo "$@"
    ## run the command and redirect it's error output
    ## to the logfile
    eval "$@"
}

printf "\n\033[1;34m******************************Start local_write_read_prefix.sh script**********************************\033[0m\n"
printf "\033[1;34mThis script writes 10 blocks of BS=4K to local store with prefix xyz . Reads back the written data and compares if done correctly.\033[0m\n"

printf "\n\033[1;34mclean up cloud store bucket first\033[0m\n"
runthis "../cloudbacker --accessFile=/home/build/.s3backer_passwd_s3 --size=10M --blockSize=4K s3://sujathas3b1 --erase --force"
runthis "../cloudbacker --accessFile=/home/build/.s3backer_passwd_s3 --size=10M --blockSize=4K --prefix=xyz s3://sujathas3b1 --erase --force"
runthis "../cloudbacker --accessFile=/home/build/.s3backer_passwd_s3 --size=10M --blockSize=4K --prefix=abc s3://sujathas3b1 --erase --force"

printf "\n\033[1;34mclean up block device\033[0m\n"
runthis "dd if=/dev/zero of=/dev/loop0 bs=4096 count=7680"

printf "\n\033[1;34mmount and write blocks to cloudstore\033[0m\n"
runthis "../cloudbacker --accessFile=/home/build/.s3backer_passwd_s3 --size=10M --blockSize=4K --prefix=xyz s3://sujathas3b1 /mnt/source/ --listBlocks --localStore=/dev/loop0"

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

printf "\n\033[1;34mremount file system with prefix=xyz\033[0m\n"
runthis "../cloudbacker --accessFile=/home/build/.s3backer_passwd_s3 --size=10M --blockSize=4K --prefix=xyz s3://sujathas3b1 /mnt/source/ --listBlocks --localStore=/dev/loop0"

printf "\n\033[1;34mread blocks written earlier\033[0m\n"
runthis "dd of=readFromlocal.txt if=/mnt/source/file bs=4096 count=10"

printf "\n\033[1;34mcompare writeTolocal.txt and readFromlocal.txt to confirm if read write worked correctly.\033[0m\n"
if diff writeTolocal.txt readFromlocal.txt >/dev/null ; then
 printf "\n\033[1;32mboth files are same\033[0m\n"
  printf "\n\033[1;32m****************** TEST 1 :: PASS ********************\033[0m\n"
else
  printf "\n\033[1;31mfiles are different\033[0m\n"
  printf "\n\033[1;31m****************** TEST 1 :: FAIL ********************\033[0m\n"

fi

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


printf "\n\033[1;34mremount file system with prefix=abc -- mounting fails\033[0m\n"
runthis "../cloudbacker --accessFile=/home/build/.s3backer_passwd_s3 --size=10M --blockSize=4K --prefix=abc s3://sujathas3b1 /mnt/source/ --listBlocks --localStore=/dev/loop0"

printf "\n\033[1;34mread blocks written earlier--should not read into file\033[0m\n"
runthis "dd of=readFromlocal.txt if=/mnt/source/file bs=4096 count=10"

printf "\n\033[1;34mcompare writeTolocal.txt and readFromlocal.txt to confirm if read write worked correctly.\033[0m\n"
if diff writeTolocal.txt readFromlocal.txt >/dev/null ; then
  printf "\n\033[1;32mboth files are same\033[0m\n"
  printf "\n\033[1;32m****************** TEST 2 :: PASS ********************\033[0m\n"
else
  printf "\n\033[1;31mfiles are different\033[0m\n"
  printf "\n\033[1;31m****************** TEST 2 :: FAIL ********************\033[0m\n"

fi

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

printf "\n\033[1;34mremount file system without any prefix -- mounting should fail due to prefix error \033[0m\n"
runthis "../cloudbacker --accessFile=/home/build/.s3backer_passwd_s3 --size=10M --blockSize=4K s3://sujathas3b1 /mnt/source/ --listBlocks --localStore=/dev/loop0"

printf "\n\033[1;34mread blocks written earlier--should not read into file\033[0m\n"
runthis "dd of=readFromlocal.txt if=/mnt/source/file bs=4096 count=10"

printf "\n\033[1;34mcompare writeTolocal.txt and readFromlocal.txt to confirm if read write worked correctly.\033[0m\n"
if diff writeTolocal.txt readFromlocal.txt >/dev/null ; then
  printf "\n\033[1;32mboth files are same\033[0m\n"
  printf "\n\033[1;32m****************** TEST 3 :: PASS ********************\033[0m\n"
else
  printf "\n\033[1;31mfiles are different\033[0m\n"
  printf "\n\033[1;31m****************** TEST 3 :: FAIL ********************\033[0m\n"

fi

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


printf "\n\033[1;34mclean up cloud store bucket\033[0m\n"
runthis "../cloudbacker --accessFile=/home/build/.s3backer_passwd_s3 --size=10M --blockSize=4K --prefix=xyz s3://sujathas3b1 --erase --force --localStore=/dev/loop0"
runthis "../cloudbacker --accessFile=/home/build/.s3backer_passwd_s3 --size=10M --blockSize=4K --prefix=abc s3://sujathas3b1 --erase --force --localStore=/dev/loop0"
runthis "../cloudbacker --accessFile=/home/build/.s3backer_passwd_s3 --size=10M --blockSize=4K s3://sujathas3b1 --erase --force --localStore=/dev/loop0"

printf "\n\033[1;31mNOTE :: cleanup read log files using command 'rm -f readFrom*.txt', if required\033[0m\n"

printf "\n\033[1;34m************************************End local_write_read_prefix.sh script*******************************************\033[0m\n"
