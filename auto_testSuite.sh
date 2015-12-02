#!/bin/bash

exe_path=$1
config_filepath=$2
if [[ $# -eq 0 ]] ; then
    exe_path=./cloudbacker
    config_filepath=auto_testConfig
fi

if [[ $# -ne 2 ]] ; then
    printf "\n\033[1;34mscript usage : auto_testSuite.sh [exe/path] [config/file/path]\033[0m"
    printf "\n\033[1;34mIf no arguments are specified then current directory files will be used with \033[0m"
    printf "\n\033[1;34mRunning script ./auto_testSuite.sh $exe_path $config_filepath \033[0m\n"   
fi

#check if file path specified is correct
function validate_path()
{
  path=$@
  if [ -f "$path" ] ; then
      echo " "
      #printf "\033[1;32mspecified path :: $path. \033[0m\n"
  else
      printf "\n\033[1;31mERROR :: incorrect path specified : $path not found. \033[0m\n"  
      exit 1
  fi
}

printf "\n\033[1;34m================================================================================== \033[0m\n"
printf "\033[1;34m                        Test Configuration details     \033[0m\n"
printf "\033[1;34m================================================================================== \033[0m\n"
#validate exe path and config file provided as command line arguments
validate_path $exe_path
printf "\033[1;36mExecutable file path           -    $exe_path          \033[0m"
validate_path $config_filepath
printf "\033[1;36mTest configuration file path   -    $config_filepath   \033[0m"
#print date and hostname
printf "\n\033[1;36mDate                           -    $(date)          \033[0m\n"
printf "\033[1;36mHostName                       -    $(hostname)        \033[0m\n"

#print cloudbacker version
printf "\n\033[1;36m===========================   cloudbacker version   =============================  \033[0m\n"
$exe_path --version

printf "\n\033[1;34m=================================================================================\033[0m\n"

printf "\n\033[1;36mStarting script execution\033[0m\n\n"

#This is the function which takes a variable length array as an input.
#Config file has all the command line arguments and flags configured in it.
#Config file is parsed line by line and assigned to below variables.
#below variables will be used as per test case.
function parse_arguments()
{
    all_array_values=$1[@]
    a=("${!all_array_values}")
	
	accessFile=${a[0]}
	accessId=${a[1]}
	accessKey=${a[2]}
	accesstype=${a[3]}
	authVersion=${a[4]}
	ec2Role=${a[5]}
	baseUrl=${a[6]}
	blockCacheFile=${a[7]}
	blockCacheMaxDirty=${a[8]}
	blockCacheNoVerify=${a[9]}
	blockCacheSize=${a[10]}
	blockCacheSync=${a[11]}
	blockCacheThreads=${a[12]}
	blockCacheTimeout=${a[13]}
	blockCacheWriteDelay=${a[14]}
	blockSize=${a[15]}
	cacert=${a[16]}
	compression=${a[17]}
	directIO=${a[18]}
	encrypt=${a[19]}
	erase=${a[20]}
	fileMode=${a[21]}
	filename=${a[22]}
	force=${a[23]}
	initialRetryPause=${a[24]}
	insecure=${a[25]}
	keyLength=${a[26]}
	listBlocks=${a[27]}
	listBlocksAsync=${a[28]}
	maxDownloadSpeed=${a[29]}
	maxRetryPause=${a[30]}
	maxUploadSpeed=${a[31]}
	md5CacheSize=${a[32]}
	md5CacheTime=${a[33]}
	minWriteDelay=${a[34]}
	password=${a[35]}
	passwordFile=${a[36]}
	maxKeys=${a[37]}
	prefix=${a[38]}
	quiet=${a[39]}
	readAhead=${a[40]}
	readAheadTrigger=${a[41]}
	nameHash=${a[42]}
	readOnly=${a[43]}
	region=${a[44]}
	reset=${a[45]}
	storageClass=${a[46]}
	filesystem_size=${a[47]}
	ssl=${a[48]}
	statsFilename=${a[49]}
	test_flag=${a[50]}
	timeout=${a[51]}
	version=${a[52]}
	vhost=${a[53]}
	bucket=${a[54]}
	mountpoint=${a[55]}
        localStore=${a[56]}
}


#Here I add all the file contents to the variable - options.
options=$(cat $config_filepath)

#In this step I convert the file contents to an array by splitting on space.
options_array=(${options//' '/ })

#I call the function here to parse options.
parse_arguments options_array

#some arguments need to be tokenized, in order to use in some test cases
arr=( $(echo $localStore | tr '=' ' ') ) # Populate the --localStore=/blk/dev/path tokens into an array
blockDevice=${arr[1]}

arr=( $(echo $filename | tr '=' ' ') ) # Populate the --filename=fileName tokens into an array
mountedfile=${arr[1]}

arr=( $(echo $bucket | tr ':' ' ') ) # Populate the bucket gs://gs-bucket or s3://s3-bucket tokens into an array
btype=${arr[0]}

if [ "$btype" == "s3" ] || [ "$btype" == "S3" ]; then
  gs_bucket=0
  s3_bucket=1
fi
if [ "$btype" == "gs" ] || [ "$btype" == "GS" ]; then
  gs_bucket=1
  s3_bucket=0
fi

#function to parse size arguments like size, blockSize etc
parseSize() {(
    local SUFFIXES=('' K M G T P E Z Y)
    local MULTIPLIER=1

    shopt -s nocasematch

    for SUFFIX in "${SUFFIXES[@]}"; do
        local REGEX="^([0-9]+)(${SUFFIX}i?B?)?\$"

        if [[ $1 =~ $REGEX ]]; then
            echo $((${BASH_REMATCH[1]} * MULTIPLIER))
           #return $((${BASH_REMATCH[1]} * MULTIPLIER))
        fi

        ((MULTIPLIER *= 1024))
    done

    #echo "$0: invalid size \`$1'" >&2
    #return 1
)}

#parse file system size
arr=( $(echo $filesystem_size | tr '=' ' ') ) # Populate the --size=10M tokens into an array
config_size=$(parseSize ${arr[1]})
#echo $config_size

#parse block size
arr=( $(echo $blockSize | tr '=' ' ') ) # Populate the --blockSize=64K tokens into an array
config_blockSize=$(parseSize ${arr[1]})
#echo $config_blockSize

runthis(){
    # print the command to the logfile
    echo "$@"
	
    # run the command and redirect it's error output to the logfile
    eval "$@"
}

#get block device size
bd_size=$(blockdev --getsize64 $blockDevice)
#echo $bd_size

#get block device physical block size
bd_blockSize=$(blockdev --getpbsz $blockDevice)
#echo $bd_blockSize

empty_block_device(){
    printf "\n\033[1;34mfree space on block device\033[0m\n"
    runthis "dd if=/dev/zero of=$blockDevice bs=$bd_blockSize count=$(($bd_size/$bd_blockSize))"
}

# variables to print summary at the end
total_executed=0
total_failed=0
total_passed=0


#Test bucket name option without any prefix- should not mount and give invalid bucket name error
invalid_bucketName_Test1(){
    ((total_executed++))
    runthis "$exe_path $accessFile $filesystem_size $blockSize invalid_bucket $mountpoint"
    if [ $? -ne 0 ]; then
       printf "\033[1;32m invalid_bucketName_Test1 :: PASS\033[0m\n\n"
      ((total_passed++))
    else
      printf "\033[1;31m invalid_bucketName_Test1 :: FAIL\033[0m\n\n"
     ((total_failed++))
   fi
}

#Test bucket name option with incorrect prefix - should not mount and give invalid bucket name error
invalid_bucketName_Test2(){
    ((total_executed++))
    runthis "$exe_path $accessFile $filesystem_size $blockSize abc://invalid_bucket $mountpoint"
    if [ $? -ne 0 ]; then
        printf "\033[1;32m invalid_bucketName_Test2 :: PASS\033[0m\n\n"
       ((total_passed++))
    else
        printf "\033[1;31m invalid_bucketName_Test2 :: FAIL\033[0m\n\n"
       ((total_failed++))
    fi
}

#Test bucket name option with incorrect prefix - should not mount and give invalid bucket name error
invalid_bucketName_Test3(){
    ((total_executed++))
    runthis "$exe_path $accessFile $filesystem_size $blockSize 12://invalid_bucket $mountpoint"
    if [ $? -ne 0 ]; then
        printf "\033[1;32m invalid_bucketName_Test3 :: PASS\033[0m\n\n"
        ((total_passed++))
    else
        printf "\033[1;31m invalid_bucketName_Test3 :: FAIL\033[0m\n\n"
        ((total_failed++))
    fi
}

#For GS - Test bucket name option with correct prefix, but bucket does not exist - should not mount
invalid_bucketName_Test4(){
    ((total_executed++))
    runthis "$exe_path $accessFile $filesystem_size $blockSize gs://nonExisting_bucket $mountpoint"
    if [ $? -ne 0 ]; then
        printf "\033[1;32m invalid_bucketName_Test4 :: PASS\033[0m\n\n"
        ((total_passed++))
    else
        printf "\033[1;31m invalid_bucketName_Test4 :: FAIL\033[0m\n\n"
        ((total_failed++))
    fi
}

#For s3 - Test bucket name option with correct prefix, but bucket does not exist - should not mount
invalid_bucketName_Test5(){
    ((total_executed++))
    runthis "$exe_path $accessFile $filesystem_size $blockSize s3://nonExisting_bucket $mountpoint"
    if [ $? -ne 0 ]; then
        printf "\033[1;32m invalid_bucketName_Test5 :: PASS\033[0m\n\n"
        ((total_passed++))
    else
        printf "\033[1;31m invalid_bucketName_Test5 :: FAIL\033[0m\n\n"
        ((total_failed++))
    fi
}

#For GS - Test bucket name option with correct prefix, empty bucket name - should not mount
invalid_bucketName_Test6(){
    ((total_executed++))
    runthis "$exe_path $accessFile $filesystem_size $blockSize gs:// $mountpoint"
    if [ $? -ne 0 ]; then
        printf "\033[1;32m invalid_bucketName_Test6 :: PASS\033[0m\n\n"
       ((total_passed++))
    else
        printf "\033[1;31m invalid_bucketName_Test6 :: FAIL\033[0m\n\n"
        ((total_failed++))
    fi
}

#For s3 - Test bucket name option with correct prefix, empty bucket name - should not mount
invalid_bucketName_Test7(){
    ((total_executed++))
    runthis "$exe_path $accessFile $filesystem_size $blockSize s3:// $mountpoint"
    if [ $? -ne 0 ]; then
        printf "\033[1;32m invalid_bucketName_Test7 :: PASS\033[0m\n\n"
       ((total_passed++))
    else
        printf "\033[1;31m invalid_bucketName_Test7 :: FAIL\033[0m\n\n"
        ((total_failed++))
    fi
}

#Test with invalid path to accessFile argument - should not mount
invalid_accessFile_Test1(){
    ((total_executed++))
    runthis "$exe_path --accessFile=/some/dummy/path $filesystem_size $blockSize $bucket $mountpoint"
    if [ $? -ne 0 ]; then
        printf "\033[1;32m invalid_accessFile_Test1 :: PASS\033[0m\n\n"
        ((total_passed++))
    else
        printf "\033[1;31m invalid_accessFile_Test1 :: FAIL\033[0m\n\n"
        ((total_failed++))
    fi
}

#Test with empty path to accessFile argument - should not mount
invalid_accessFile_Test2(){
    ((total_executed++))
    runthis "$exe_path --accessFile= $filesystem_size $blockSize $bucket $mountpoint"
    if [ $? -ne 0 ]; then
       printf "\033[1;32m invalid_accessFile_Test2 :: PASS\033[0m\n\n"
      ((total_passed++))
    else
       printf "\033[1;31m invalid_accessFile_Test2 :: FAIL\033[0m\n\n"
       ((total_failed++))
    fi
}

#Test with invalid accessId and valid accessKey argument - should not mount
invalid_accessId_Key_Test1(){
    ((total_executed++))
    runthis "$exe_path --accessId=dummyAccessID $accesskey $filesystem_size $blockSize $bucket $mountpoint"
    if [ $? -ne 0 ]; then
        printf "\033[1;32m invalid_accessId_Key_Test1 :: PASS\033[0m\n\n"
       ((total_passed++))
    else
        printf "\033[1;31m invalid_accessId_Key_Test1 :: FAIL\033[0m\n\n"
        ((total_failed++))
    fi
}

#Test with valid accessId and invalid accessKey argument - should not mount
invalid_accessId_Key_Test2(){
     ((total_executed++))
     runthis "$exe_path $accessId --accesskey=dummyAccessKey $filesystem_size $blockSize $bucket $mountpoint"
     if [ $? -ne 0 ]; then
         printf "\033[1;32m invalid_accessId_Key_Test2 :: PASS\033[0m\n\n"
         ((total_passed++))
     else
         printf "\033[1;31m invalid_accessId_Key_Test2 :: FAIL\033[0m\n\n"
         ((total_failed++))
     fi
}

#Test with invalid accessType argument - should not mount
invalid_accessType_Test1(){
    ((total_executed++))
    runthis "$exe_path $accessFile --accessType=dummy $filesystem_size $blockSize $bucket $mountpoint"
    if [ $? -ne 0 ]; then
        printf "\033[1;32m invalid_accessType_Test1 :: PASS\033[0m\n\n"
        ((total_passed++))
    else
        printf "\033[1;31m invalid_accessType_Test1 :: FAIL\033[0m\n\n"
        ((total_failed++))
    fi
}

#Test with invalid authVersion argument - should not mount
invalid_authVersion_Test1(){
    ((total_executed++))
    runthis "$exe_path $accessFile --authVersion=dummy $filesystem_size $blockSize $bucket $mountpoint"
    if [ $? -ne 0 ]; then
        printf "\033[1;32m invalid_authVersion_Test1 :: PASS\033[0m\n\n"
       ((total_passed++))
    else
       printf "\033[1;31m invalid_authVersion_Test1 :: FAIL\033[0m\n\n"
      ((total_failed++))
    fi
}

#Test with empty value for authVersion argument - should not mount
invalid_authVersion_Test2(){
    ((total_executed++))
    runthis "$exe_path $accessFile --authVersion= $filesystem_size $blockSize $bucket $mountpoint"
    if [ $? -ne 0 ]; then
       printf "\033[1;32m invalid_authVersion_Test2 :: PASS\033[0m\n\n"
       ((total_passed++))
    else
       printf "\033[1;31m invalid_authVersion_Test2 :: FAIL\033[0m\n\n"
       ((total_failed++))
    fi
}

#Test with invalid value for baseURL argument(use http) - should not mount
invalid_baseURL_Test1(){
    ((total_executed++))
    runthis "$exe_path $accessFile --baseURL=http://some-base-url $filesystem_size $blockSize $bucket $mountpoint"
    if [ $? -ne 0 ]; then
        printf "\033[1;32m invalid_baseURL_Test1 :: PASS\033[0m\n\n"
       ((total_passed++))
    else
       printf "\033[1;31m invalid_baseURL_Test1 :: FAIL\033[0m\n\n"
       ((total_failed++))
    fi
}

#Test with empty value for baseURL argument - should not mount
invalid_baseURL_Test2(){
    ((total_executed++))
    runthis "$exe_path $accessFile --baseURL= $filesystem_size $blockSize $bucket $mountpoint"
    if [ $? -ne 0 ]; then
        printf "\033[1;32m invalid_baseURL_Test2 :: PASS\033[0m\n\n"
       ((total_passed++))
    else
        printf "\033[1;31m invalid_baseURL_Test2 :: FAIL\033[0m\n\n"
       ((total_failed++))
    fi
}

#Test with invalid value for baseURL argument(use https) - should not mount
invalid_baseURL_Test3(){
    ((total_executed++))
    runthis "$exe_path $accessFile --baseURL=https://some-base-url $filesystem_size $blockSize $bucket $mountpoint"
    if [ $? -ne 0 ]; then
       printf "\033[1;32m invalid_baseURL_Test3 :: PASS\033[0m\n\n"
      ((total_passed++))
    else
       printf "\033[1;31m invalid_baseURL_Test3 :: FAIL\033[0m\n\n"
       ((total_failed++))
    fi
}

#Test with invalid value for baseURL argument(use https) - should not mount
invalid_baseURL_Test4(){
    ((total_executed++))
    runthis "$exe_path $accessFile --baseURL=https://some-base-url/sub-url $filesystem_size $blockSize $bucket $mountpoint"
    if [ $? -ne 0 ]; then
        printf "\033[1;32m invalid_baseURL_Test4 :: PASS\033[0m\n\n"
       ((total_passed++))
    else
       printf "\033[1;31m invalid_baseURL_Test4 :: FAIL\033[0m\n\n"
       ((total_failed++))
    fi
}

#Test with invalid value for blockSize argument - should not mount
invalid_blockSize_Test1(){
    ((total_executed++))
    runthis "$exe_path $accessFile $filesystem_size --blockSize=3k $bucket $mountpoint"
    if [ $? -ne 0 ]; then
        printf "\033[1;32m invalid_blockSize_Test1 :: PASS\033[0m\n\n"
       ((total_passed++))
    else
        printf "\033[1;31m invalid_blockSize_Test1 :: FAIL\033[0m\n\n"
       ((total_failed++))
    fi
}

#Test with empty value for blockSize argument - should not mount
invalid_blockSize_Test2(){
    ((total_executed++))
    runthis "$exe_path $accessFile $filesystem_size --blockSize $bucket $mountpoint"
    if [ $? -ne 0 ]; then
        printf "\033[1;32m invalid_blockSize_Test2 :: PASS\033[0m\n\n"
       ((total_passed++))
    else
        printf "\033[1;31m invalid_blockSize_Test2 :: FAIL\033[0m\n\n"
       ((total_failed++))
    fi
}

#Test with invalid value for fileMode argument - should not mount
invalid_filemode_Test1(){
    ((total_executed++))
    runthis "$exe_path $accessFile $filesystem_size $blockSize --fileMode=888 $bucket $mountpoint"
    if [ $? -ne 0 ]; then
        printf "\033[1;32m invalid_filemode_Test1 :: PASS\033[0m\n\n"
       ((total_passed++))
    else
        printf "\033[1;31m invalid_filemode_Test1 :: FAIL\033[0m\n\n"
        ((total_failed++))
    fi
}

#Test with empty value for fileMode argument - should not mount
invalid_filemode_Test2(){
    ((total_executed++))
    runthis "$exe_path $accessFile $filesystem_size $blockSize --fileMode= $bucket $mountpoint"
    if [ $? -ne 0 ]; then
        printf "\033[1;32m invalid_filemode_Test2 :: PASS\033[0m\n\n"
       ((total_passed++))
    else
        printf "\033[1;31m invalid_filemode_Test2 :: FAIL\033[0m\n\n"
       ((total_failed++))
    fi
}

#Test with invalid value for fileMode argument - should not mount
invalid_filemode_Test3(){
    ((total_executed++))
    runthis "$exe_path $accessFile $filesystem_size $blockSize --fileMode=866 $bucket $mountpoint"
    if [ $? -ne 0 ]; then
        printf "\033[1;32m invalid_filemode_Test3 :: PASS\033[0m\n\n"
       ((total_passed++))
    else
        printf "\033[1;31m invalid_filemode_Test3 :: FAIL\033[0m\n\n"
       ((total_failed++))
    fi
}

#Test with empty value for fileName argument - should not mount
invalid_filename_Test1(){
    ((total_executed++))
    runthis "$exe_path $accessFile $filesystem_size $blockSize --filename= $bucket $mountpoint"
    if [ $? -ne 0 ]; then
       printf "\033[1;32m invalid_filename_Test1 :: PASS\033[0m\n\n"
      ((total_passed++))
    else
       printf "\033[1;31m invalid_filename_Test1 :: FAIL\033[0m\n\n"
      ((total_failed++))
    fi
}

#Test with invalid value for fileName argument - should not mount
invalid_filename_Test2(){
    ((total_executed++))
    runthis "$exe_path $accessFile $filesystem_size $blockSize --filename=/ $bucket $mountpoint"
    if [ $? -ne 0 ]; then
       printf "\033[1;32m invalid_filename_Test2 :: PASS\033[0m\n\n"
       ((total_passed++))
    else
       printf "\033[1;31m invalid_filename_Test2 :: FAIL\033[0m\n\n"
      ((total_failed++))
    fi
}

#Test with empty value for stats fileName argument - should not mount
invalid_stats_filename_Test1(){
    ((total_executed++))
    runthis "$exe_path $accessFile $filesystem_size $blockSize --statsFilename= $bucket $mountpoint"
    if [ $? -ne 0 ]; then
        printf "\033[1;32m invalid_stats_filename_Test1 :: PASS\033[0m\n\n"
       ((total_passed++))
    else
        printf "\033[1;31m invalid_stats_filename_Test1 :: FAIL\033[0m\n\n"
       ((total_failed++))
    fi
}

#Test with invalid value for stats fileName argument - should not mount
invalid_stats_filename_Test2(){
     ((total_executed++))
     runthis "$exe_path $accessFile $filesystem_size $blockSize --statsFilename=/ $bucket $mountpoint"
     if [ $? -ne 0 ]; then
        printf "\033[1;32m invalid_stats_filename_Test2 :: PASS\033[0m\n\n"
        ((total_passed++))
     else
        printf "\033[1;31m invalid_stats_filename_Test2 :: FAIL\033[0m\n\n"
        ((total_failed++))
     fi
}

#Test with invalid value for region argument - should not mount
invalid_region_Test1(){
    ((total_executed++))
    runthis "$exe_path $accessFile $filesystem_size $blockSize --region=dummy $bucket $mountpoint"
    if [ $? -ne 0 ]; then
        printf "\033[1;32m invalid_region_Test1 :: PASS\033[0m\n\n"
       ((total_passed++))
    else
        printf "\033[1;31m invalid_region_Test1 :: FAIL\033[0m\n\n"
       ((total_failed++))
    fi
}

#Test with empty value for region argument - should not mount
invalid_region_Test2(){
    ((total_executed++))
    runthis "$exe_path $accessFile $filesystem_size $blockSize --region= $bucket $mountpoint"
    if [ $? -ne 0 ]; then
        printf "\033[1;32m invalid_region_Test2 :: PASS\033[0m\n\n"
        ((total_passed++))
    else
        printf "\033[1;31m invalid_region_Test2 :: FAIL\033[0m\n\n"
        ((total_failed++))
    fi
}

#Test with invalid value for region argument - should not mount
invalid_region_Test3(){
    ((total_executed++))
    runthis "$exe_path $accessFile $filesystem_size $blockSize --region=us-south $bucket $mountpoint"
    if [ $? -ne 0 ]; then
        printf "\033[1;32m invalid_region_Test3 :: PASS\033[0m\n\n"
        ((total_passed++))
    else
        printf "\033[1;31m invalid_region_Test3 :: FAIL\033[0m\n\n"
        ((total_failed++))
    fi
}

#Test with invalid value for storageClass argument - should not mount
invalid_storageClass_Test1(){
    ((total_executed++))
    runthis "$exe_path $accessFile $filesystem_size $blockSize --storageClass=invalid_class $bucket $mountpoint"
    if [ $? -ne 0 ]; then
        printf "\033[1;32m invalid_storageClass_Test1 :: PASS\033[0m\n\n"
        ((total_passed++))
    else
        printf "\033[1;31m invalid_storageClass_Test1 :: FAIL\033[0m\n\n"
        ((total_failed++))
    fi
    unmount_filesystem
}

#Test with empty value for storageClass argument - should not mount
invalid_storageClass_Test2(){
    ((total_executed++))
    runthis "$exe_path $accessFile $filesystem_size $blockSize --storageClass= $bucket $mountpoint"
    if [ $? -ne 0 ]; then
        printf "\033[1;32m invalid_storageClass_Test2 :: PASS\033[0m\n\n"
        ((total_passed++))
    else
        printf "\033[1;31m invalid_storageClass_Test2 :: FAIL\033[0m\n\n"
        ((total_failed++))
    fi
    unmount_filesystem
}

#Test with non default value for storageClass argument - should not mount
invalid_storageClass_Test3(){
    ((total_executed++))
    runthis "$exe_path $accessFile $filesystem_size $blockSize --storageClass=DURABLE_REDUCED_AVAILABILITY $bucket $mountpoint"
    if [ $? -ne 0 ]; then
        printf "\033[1;32m invalid_storageClass_Test3 :: PASS\033[0m\n\n"
        ((total_passed++))
    else
        printf "\033[1;31m invalid_storageClass_Test3 :: FAIL\033[0m\n\n"
        ((total_failed++))
    fi
    unmount_filesystem
}

#Test with non default value for storageClass argument - should not mount
invalid_storageClass_Test4(){
    ((total_executed++))
    if [ $gs_bucket -eq 1]; then
        runthis "$exe_path $accessFile $filesystem_size $blockSize --storageClass=REDUCED_REDUNDANCY $bucket $mountpoint"
    else
        runthis "$exe_path $accessFile $filesystem_size $blockSize --storageClass=DURABLE_REDUCED_AVAILABILITY $bucket $mountpoint"
    fi 
    if [ $? -ne 0 ]; then
        printf "\033[1;32m invalid_storageClass_Test4 :: PASS\033[0m\n\n"
        ((total_passed++))
    else
        printf "\033[1;31m invalid_storageClass_Test4 :: FAIL\033[0m\n\n"
        ((total_failed++))
    fi
    unmount_filesystem
}

#Test with incorrect file system size, not a multiple of 2
invalid_filesize_Test1(){
    ((total_executed++))
    runthis "$exe_path $accessFile --size=$(($config_size+1)) $blockSize $bucket $mountpoint $filename"
    if [ $? -ne 0 ]; then
       printf "\033[1;32m invalid_filesize_Test1 :: PASS\033[0m\n\n"
       ((total_passed++))
    else
       printf "\033[1;31m invalid_filesize_Test1 :: FAIL\033[0m\n\n"
       ((total_failed++))
    fi
    
}

#Test with incorrect file system size, multiple of 2, but not multiple of block size
invalid_filesize_Test2(){
    ((total_executed++))
    runthis "$exe_path $accessFile --size=$(($config_size+2)) $blockSize $bucket $mountpoint $filename"
    if [ $? -ne 0 ]; then
       printf "\033[1;32m invalid_filesize_Test2 :: PASS\033[0m\n\n"
       ((total_passed++))
    else
       printf "\033[1;31m invalid_filesize_Test2 :: FAIL\033[0m\n\n"
       ((total_failed++))
    fi
    
}

#Test with incorrect block size, not a multiple of 2
invalid_blocksize_Test1(){
    ((total_executed++))
    runthis "$exe_path $accessFile $filesystem_size --blockSize=$(($config_blockSize+1)) $bucket $mountpoint $filename"
    if [ $? -ne 0 ]; then
       printf "\033[1;32m invalid_blocksize_Test1 :: PASS\033[0m\n\n"
       ((total_passed++))
    else
       printf "\033[1;31m invalid_blocksize_Test1 :: FAIL\033[0m\n\n"
       ((total_failed++))
    fi
    
}

#Test with mount file system first and then mount with different file system size-metadata handling
invalid_metadata_filesize_Test1(){
    ((total_executed++))
    runthis "$exe_path $accessFile $filesystem_size $blockSize $bucket $mountpoint $filename"
    if [ $? -eq 0 ]; then
        unmount_filesystem
        printf "\n\033[1;34mmount with other file system size\033[0m\n"
        runthis "$exe_path $accessFile --size=$(($config_size*2)) $blockSize $bucket $mountpoint $filename"
        if [ $? -ne 0 ]; then
            printf "\033[1;32m invalid_metadata_filesize_Test1 :: PASS\033[0m\n\n"
            ((total_passed++))
        else
	     unmount_filesystem
	     printf "\033[1;31m invalid_metadata_filesize_Test1 :: FAIL\033[0m\n\n"
	     ((total_failed++))
	fi
    else	
        printf "\033[1;31m invalid_metadata_filesize_Test1 :: FAIL\033[0m\n\n"
	((total_failed++))
    fi
    printf "\033[1;34merase from bucket\033[0m\n"
    runthis "$exe_path $accessFile $filesystem_size $blockSize $bucket $filename $erase $force"    
    runthis "$exe_path $accessFile --size=$(($config_size*2)) $blockSize $bucket $filename $erase $force"
}

#Test with mount file system first and then mount with different blockSize-metadata handling
invalid_metadata_blockSize_Test1(){
    ((total_executed++))
    runthis "$exe_path $accessFile $filesystem_size $blockSize $bucket $mountpoint $filename"
    if [ $? -eq 0 ]; then
        unmount_filesystem
        printf "\n\033[1;34mmount with other block size\033[0m\n"
        runthis "$exe_path $accessFile $filesystem_size --blockSize=$(($config_blockSize*2)) $bucket $mountpoint $filename"
    	if [ $? -ne 0 ]; then
    	    printf "\033[1;32m invalid_metadata_blockSize_Test1 :: PASS\033[0m\n\n"
	   ((total_passed++))
	else
	    unmount_filesystem
	    printf "\033[1;31m invalid_metadata_blockSize_Test1 :: FAIL\033[0m\n\n"
	   ((total_failed++))
	fi
    else	
	printf "\033[1;31m invalid_metadata_blockSize_Test1 :: FAIL\033[0m\n\n"
	((total_failed++))
    fi
    
    printf "\033[1;34merase from bucket\033[0m\n"
    runthis "$exe_path $accessFile $filesystem_size $blockSize $bucket $filename $erase $force"    
    runthis "$exe_path $accessFile $filesystem_size --blockSize=$(($config_blockSize*2)) $bucket $filename $erase $force"
}

#Test with mount file system first and then mount without blockSize-metadata handling
autoDetect_metadata_blockSize_Test1(){
    ((total_executed++))
    runthis "$exe_path $accessFile $filesystem_size $blockSize $bucket $mountpoint $filename"
    if [ $? -eq 0 ]; then
        unmount_filesystem
        printf "\n\033[1;34mmount without blockSize argument\033[0m\n"
        runthis "$exe_path $accessFile $filesystem_size $bucket $mountpoint $filename"
        if [ $? -ne 0 ]; then
            printf "\033[1;31m autoDetect_metadata_blockSize_Test1 :: FAIL\033[0m\n\n"
            ((total_failed++))
        else
            unmount_filesystem
            printf "\033[1;32m autoDetect_metadata_blockSize_Test1 :: PASS\033[0m\n\n"
            ((total_passed++))
        fi
    else	
	printf "\033[1;31m autoDetect_metadata_blockSize_Test1 :: FAIL\033[0m\n\n"
	((total_failed++))
    fi
	
    printf "\033[1;34merase from bucket\033[0m\n"
    runthis "$exe_path $accessFile $filesystem_size $blockSize $bucket $filename $erase $force"    	
}

#Test with mount file system first with nameHash and then mount without nameHash-metadata handling
autoDetect_metadata_nameHash_Test1(){
    ((total_executed++))
    printf "\n\033[1;34mmount with nameHash flag\033[0m\n"
    runthis "$exe_path $accessFile $filesystem_size $blockSize $bucket $mountpoint $filename --nameHash"
    if [ $? -eq 0 ]; then
        unmount_filesystem
        printf "\n\033[1;34mmount without nameHash flag\033[0m\n"
        runthis "$exe_path $accessFile $filesystem_size $blockSize $bucket $mountpoint $filename"
    	if [ $? -ne 0 ]; then
    	    printf "\033[1;31m autoDetect_metadata_nameHash_Test1 :: FAIL\033[0m\n\n"
	    ((total_failed++))
	else
	    unmount_filesystem
	    printf "\033[1;32m autoDetect_metadata_nameHash_Test1 :: PASS\033[0m\n\n"
	   ((total_passed++))
	fi
    else	
	printf "\033[1;31m autoDetect_metadata_nameHash_Test1 :: FAIL\033[0m\n\n"
	((total_failed++))
    fi
	
    printf "\033[1;34merase from bucket\033[0m\n"
    runthis "$exe_path $accessFile $filesystem_size $blockSize $bucket $filename $erase $force --nameHash"    	
}

#Test with mount file system first without nameHash and then mount with nameHash-metadata handling
autoDetect_metadata_nameHash_Test2(){
    ((total_executed++))
    printf "\n\033[1;34mmount without nameHash flag\033[0m\n"
    runthis "$exe_path $accessFile $filesystem_size $blockSize $bucket $mountpoint $filename"
    if [ $? -eq 0 ]; then
        unmount_filesystem
        printf "\n\033[1;34mmount with nameHash flag\033[0m\n"
        runthis "$exe_path $accessFile $filesystem_size $blockSize $bucket $mountpoint $filename --nameHash"
    	if [ $? -ne 0 ]; then
	   printf "\033[1;32m autoDetect_metadata_nameHash_Test2 :: PASS\033[0m\n\n"
	   ((total_passed++))
	else
	   unmount_filesystem
	   printf "\033[1;31m autoDetect_metadata_nameHash_Test2 :: FAIL\033[0m\n\n"
	   ((total_failed++))
	fi
    else	
	printf "\033[1;31m autoDetect_metadata_nameHash_Test2 :: FAIL\033[0m\n\n"
	((total_failed++))
    fi
	
    printf "\033[1;34merase from bucket\033[0m\n"
    runthis "$exe_path $accessFile $filesystem_size $blockSize $bucket $filename $erase $force"    	
}

#Test with mount file system first without encryption and then mount with encryption-metadata handling
autoDetect_metadata_encryption_Test1(){
    ((total_executed++))
    printf "\n\033[1;34mmount without encryption flag\033[0m\n"
    runthis "$exe_path $accessFile $filesystem_size $blockSize $bucket $mountpoint $filename"
    if [ $? -eq 0 ]; then
        unmount_filesystem
        printf "\n\033[1;34mmount with encryption flag\033[0m\n"
        runthis "$exe_path $accessFile $filesystem_size $blockSize $bucket $mountpoint $filename --encrypt --compress --password=abcd"
        if [ $? -ne 0 ]; then
           printf "\033[1;32m autoDetect_metadata_encryption_Test1 :: PASS\033[0m\n\n"
           ((total_passed++))
        else
           unmount_filesystem
           printf "\033[1;31m autoDetect_metadata_encryption_Test1 :: FAIL\033[0m\n\n"
           ((total_failed++))
        fi
    else
        printf "\033[1;31m autoDetect_metadata_encryption_Test1 :: FAIL\033[0m\n\n"
        ((total_failed++))
    fi

    printf "\033[1;34merase from bucket\033[0m\n"
    runthis "$exe_path $accessFile $filesystem_size $blockSize $bucket $filename $erase $force"
    runthis "$exe_path $accessFile $filesystem_size $blockSize $bucket $filename $erase $force --encrypt --compress --password=abcd"
}

#Test with mount file system first with encryption and then mount without encryption-metadata handling
autoDetect_metadata_encryption_Test2(){
    ((total_executed++))
    printf "\n\033[1;34mmount with encryption flag\033[0m\n"
    runthis "$exe_path $accessFile $filesystem_size $blockSize $bucket $mountpoint $filename --encrypt --compress --password=abcd"
    if [ $? -eq 0 ]; then
        unmount_filesystem
        printf "\n\033[1;34mmount without encryption flag\033[0m\n"
        runthis "$exe_path $accessFile $filesystem_size $blockSize $bucket $mountpoint $filename"
        if [ $? -ne 0 ]; then
           printf "\033[1;32m autoDetect_metadata_encryption_Test2 :: PASS\033[0m\n\n"
           ((total_passed++))
        else
           unmount_filesystem
           printf "\033[1;31m autoDetect_metadata_encryption_Test2 :: FAIL\033[0m\n\n"
           ((total_failed++))
        fi
    else
        printf "\033[1;31m autoDetect_metadata_encryption_Test2 :: FAIL\033[0m\n\n"
        ((total_failed++))
    fi

    printf "\033[1;34merase from bucket\033[0m\n"
    runthis "$exe_path $accessFile $filesystem_size $blockSize $bucket $filename $erase $force"
    runthis "$exe_path $accessFile $filesystem_size $blockSize $bucket $filename $erase $force --encrypt --compress --password=abcd"
}

#Test with encryption-metadata handling
autoDetect_metadata_encryption_Test3(){
    ((total_executed++))
    printf "\n\033[1;34mmount with default encryption cipher\033[0m\n"
    runthis "$exe_path $accessFile $filesystem_size $blockSize $bucket $mountpoint $filename --encrypt --compress --password=abcd"
    if [ $? -eq 0 ]; then
        unmount_filesystem
        printf "\n\033[1;34mmount with other encryption cipher\033[0m\n"
        runthis "$exe_path $accessFile $filesystem_size $blockSize $bucket $mountpoint $filename --encrypt=AES-256-CBC --compress --password=abcd"
        if [ $? -ne 0 ]; then
           printf "\033[1;32m autoDetect_metadata_encryption_Test3 :: PASS\033[0m\n\n"
           ((total_passed++))
        else
           unmount_filesystem
           printf "\033[1;31m autoDetect_metadata_encryption_Test3 :: FAIL\033[0m\n\n"
           ((total_failed++))
        fi
    else
        printf "\033[1;31m autoDetect_metadata_encryption_Test3 :: FAIL\033[0m\n\n"
        ((total_failed++))
    fi

    printf "\033[1;34merase from bucket\033[0m\n"
    runthis "$exe_path $accessFile $filesystem_size $blockSize $bucket $filename $erase $force --encrypt --compress --password=abcd"
}

#Test with encryption-metadata handling
autoDetect_metadata_encryption_Test4(){
    ((total_executed++))
    printf "\n\033[1;34mmount with default encryption cipher\033[0m\n"
    runthis "$exe_path $accessFile $filesystem_size $blockSize $bucket $mountpoint $filename --encrypt --compress --password=abcd"
    if [ $? -eq 0 ]; then
        unmount_filesystem
        printf "\n\033[1;34mmount with other encryption cipher\033[0m\n"
        runthis "$exe_path $accessFile $filesystem_size $blockSize $bucket $mountpoint $filename --encrypt=decrypt --compress --password=abcd"
        if [ $? -ne 0 ]; then
           printf "\033[1;32m autoDetect_metadata_encryption_Test4 :: PASS\033[0m\n\n"
           ((total_passed++))
        else
           unmount_filesystem
           printf "\033[1;31m autoDetect_metadata_encryption_Test4 :: FAIL\033[0m\n\n"
           ((total_failed++))
        fi
    else
        printf "\033[1;31m autoDetect_metadata_encryption_Test4 :: FAIL\033[0m\n\n"
        ((total_failed++))
    fi

    printf "\033[1;34merase from bucket\033[0m\n"
    runthis "$exe_path $accessFile $filesystem_size $blockSize $bucket $filename $erase $force --encrypt --compress --password=abcd"
}

#Test with compression-metadata handling
autoDetect_metadata_compress_Test1(){
    ((total_executed++))
    printf "\n\033[1;34mmount with default encryption cipher and compression = 2\033[0m\n"
    runthis "$exe_path $accessFile $filesystem_size $blockSize $bucket $mountpoint $filename --encrypt --compress=2 --password=abcd"
    if [ $? -eq 0 ]; then
        unmount_filesystem
        printf "\n\033[1;34mmount with default encryption cipher and compression = 1\033[0m\n"
        runthis "$exe_path $accessFile $filesystem_size $blockSize $bucket $mountpoint $filename --encrypt --compress=1 --password=abcd"
        if [ $? -ne 0 ]; then
           printf "\033[1;32m autoDetect_metadata_compress_Test1 :: PASS\033[0m\n\n"
           ((total_passed++))
        else
           unmount_filesystem
           printf "\033[1;31m autoDetect_metadata_compress_Test1 :: FAIL\033[0m\n\n"
           ((total_failed++))
        fi
    else
        printf "\033[1;31m autoDetect_metadata_compress_Test1 :: FAIL\033[0m\n\n"
        ((total_failed++))
    fi

    printf "\033[1;34merase from bucket\033[0m\n"
    runthis "$exe_path $accessFile $filesystem_size $blockSize $bucket $filename $erase $force --encrypt --compress=2 --password=abcd"
}

#Test with compression-metadata handling
autoDetect_metadata_compress_Test2(){
    ((total_executed++))
    printf "\n\033[1;34mmount with default encryption cipher and default compression\033[0m\n"
    runthis "$exe_path $accessFile $filesystem_size $blockSize $bucket $mountpoint $filename --encrypt --compress --password=abcd"
    if [ $? -eq 0 ]; then
        unmount_filesystem
        printf "\n\033[1;34mmount with default encryption cipher and compression = 1\033[0m\n"
        runthis "$exe_path $accessFile $filesystem_size $blockSize $bucket $mountpoint $filename --encrypt --compress=1 --password=abcd"
        if [ $? -ne 0 ]; then
           printf "\033[1;32m autoDetect_metadata_compress_Test2 :: PASS\033[0m\n\n"
           ((total_passed++))
        else
           unmount_filesystem
           printf "\033[1;31m autoDetect_metadata_compress_Test2 :: FAIL\033[0m\n\n"
           ((total_failed++))
        fi
    else
        printf "\033[1;31m autoDetect_metadata_compress_Test2 :: FAIL\033[0m\n\n"
        ((total_failed++))
    fi

    printf "\033[1;34merase from bucket\033[0m\n"
    runthis "$exe_path $accessFile $filesystem_size $blockSize $bucket $filename $erase $force --encrypt --compress --password=abcd"
}

#Test with compression, encryption-metadata handling
autoDetect_metadata_compress_Test3(){
    ((total_executed++))
    printf "\n\033[1;34mmount with encryption cipher=AES-256-CBC and compression=1\033[0m\n"
    runthis "$exe_path $accessFile $filesystem_size $blockSize $bucket $mountpoint $filename --encrypt=AES-256-CBC --compress=1 --password=abcd"
    if [ $? -eq 0 ]; then
        unmount_filesystem
        printf "\n\033[1;34mmount with encryption cipher=AES-128-CBC and compression=1\033[0m\n"
        runthis "$exe_path $accessFile $filesystem_size $blockSize $bucket $mountpoint $filename --encrypt=AES-128-CBC --compress=1 --password=abcd"
        if [ $? -ne 0 ]; then
           printf "\033[1;32m autoDetect_metadata_compress_Test3 :: PASS\033[0m\n\n"
           ((total_passed++))
        else
           unmount_filesystem
           printf "\033[1;31m autoDetect_metadata_compress_Test3 :: FAIL\033[0m\n\n"
           ((total_failed++))
        fi
    else
        printf "\033[1;31m autoDetect_metadata_compress_Test3 :: FAIL\033[0m\n\n"
        ((total_failed++))
    fi

    printf "\033[1;34merase from bucket\033[0m\n"
    runthis "$exe_path $accessFile $filesystem_size $blockSize $bucket $filename $erase $force --encrypt=AES-256-CBC --compress=1  --password=abcd"
}

#This test writes random data 25 blocks of configured block size to cloud store. Reads back 25 blocks of data and compares if done correctly
cloud_read_write_Test1(){

    #prepare data
    runthis "touch cloud_writeData cloud_readData"
    runthis "dd if=/dev/urandom of=cloud_writeData bs=$config_blockSize count=25"

    ((total_executed++))

    printf "\n\033[1;34mmount and write blocks to cloudstore\033[0m\n"
    runthis "$exe_path $accessFile $filesystem_size $blockSize $bucket $mountpoint $filename"

    printf "\n\033[1;34mwrite blocks to cloudstore\033[0m\n"
    runthis "dd if=cloud_writeData of=$mountpoint/$mountedfile bs=$config_blockSize count=25"

    unmount_filesystem

    printf "\n\033[1;34mremount file system\033[0m\n"
    runthis "$exe_path $accessFile $filesystem_size $blockSize $bucket $mountpoint $filename"

    printf "\n\033[1;34mread blocks written earlier to cloudstore\033[0m\n"
    runthis "dd of=cloud_readData if=$mountpoint/$mountedfile bs=$config_blockSize count=25"

    printf "\n\033[1;34mcompare cloud_writeData and cloud_readData to confirm if read write worked correctly.files should be same\033[0m\n"
    if diff cloud_writeData cloud_readData  > /dev/null ; then
        printf "\033[1;32m cloud_read_write_Test1 :: PASS\033[0m\n\n"
       ((total_passed++))
    else
        printf "\033[1;31m cloud_read_write_Test1 :: FAIL\033[0m\n\n"
        ((total_failed++))
    fi

    unmount_filesystem

	rm -f cloud_writeData cloud_readData
    printf "\033[1;34merase all blocks\033[0m\n"
    runthis "$exe_path $accessFile $filesystem_size $blockSize $bucket $erase $force $filename"
}

#This test tries to write random data 25 blocks of configured block size to cloud store mounted with readOnly flag. Reads back 25 blocks of data and compares if done correctly
cloud_read_write_Test2(){

    #prepare data
    runthis "touch cloud_writeData cloud_readData"
    runthis "dd if=/dev/urandom of=cloud_writeData bs=$config_blockSize count=25"

    ((total_executed++))

    printf "\n\033[1;34mmount with readOnly flag and write blocks to cloudstore\033[0m\n"
    runthis "$exe_path $accessFile $filesystem_size $blockSize $bucket $mountpoint $filename $readOnly"

    printf "\n\033[1;34mwrite blocks to cloudstore\033[0m\n"
    runthis "dd if=cloud_writeData of=$mountpoint/$mountedfile bs=$config_blockSize count=25"

    unmount_filesystem

    printf "\n\033[1;34mremount file system with readOnly flag \033[0m\n"
    runthis "$exe_path $accessFile $filesystem_size $blockSize $bucket $mountpoint $filename $readOnly"

    printf "\n\033[1;34mread blocks written earlier to cloudstore\033[0m\n"
    runthis "dd of=cloud_readData if=$mountpoint/$mountedfile bs=$config_blockSize count=25"

    printf "\n\033[1;34mcompare cloud_writeData and cloud_readData to confirm if read write worked correctly.files should be different\033[0m\n"
    if diff cloud_writeData cloud_readData  > /dev/null ; then
        printf "\033[1;31m cloud_read_write_Test2 :: FAIL\033[0m\n\n"
       ((total_failed++))
    else
        printf "\033[1;32m cloud_read_write_Test2 :: PASS\033[0m\n\n"
        ((total_passed++))
    fi

    unmount_filesystem

    rm -f cloud_writeData cloud_readData
    printf "\033[1;34merase all blocks\033[0m\n"
    runthis "$exe_path $accessFile $filesystem_size $blockSize $bucket $erase $force $filename"
}

#This test writes random data 25 blocks of configured block size to cloud store, deletes 10 blocks. Reads back 25 blocks of data and compares if done correctly
cloud_read_write_Test3(){

    #prepare data
    runthis "touch cloud_writeData cloud_readData"
    runthis "dd if=/dev/urandom of=cloud_writeData bs=$config_blockSize count=25"

    ((total_executed++))

    printf "\n\033[1;34mmount and write blocks to cloudstore\033[0m\n"
    runthis "$exe_path $accessFile $filesystem_size $blockSize $bucket $mountpoint $filename"

    printf "\n\033[1;34mwrite blocks to cloudstore\033[0m\n"
    runthis "dd if=cloud_writeData of=$mountpoint/$mountedfile bs=$config_blockSize count=25"

    unmount_filesystem

    printf "\n\033[1;34mremount file system\033[0m\n"
    runthis "$exe_path $accessFile $filesystem_size $blockSize $bucket $mountpoint $filename"

    printf "\n\033[1;34mwrite zero blocks to cloudstore/ delete blocks\033[0m\n"
    runthis "dd if=/dev/zero of=$mountpoint/$mountedfile bs=$config_blockSize count=10"
	
    unmount_filesystem
    
    printf "\n\033[1;34mremount file system\033[0m\n"
    runthis "$exe_path $accessFile $filesystem_size $blockSize $bucket $mountpoint $filename"
	
	printf "\n\033[1;34mread blocks written earlier to cloudstore\033[0m\n"
    runthis "dd of=cloud_readData if=$mountpoint/$mountedfile bs=$config_blockSize count=25"
	
    printf "\n\033[1;34mcompare cloud_writeData and cloud_readData to confirm if read write worked correctly.files should be different\033[0m\n"
    if diff cloud_writeData cloud_readData  > /dev/null ; then
        printf "\033[1;31m cloud_read_write_Test3 :: FAIL\033[0m\n\n"
       ((total_failed++))
    else
        printf "\033[1;32m cloud_read_write_Test3 :: PASS\033[0m\n\n"
        ((total_passed++))
    fi

    unmount_filesystem

    rm -f cloud_writeData cloud_readData
    printf "\033[1;34merase all blocks\033[0m\n"
    runthis "$exe_path $accessFile $filesystem_size $blockSize $bucket $erase $force $filename"
}

#This test writes random data 25 blocks of configured block size to cloud store. Reads back 25 blocks with partial block reading of data and compares if done correctly
cloud_partial_read_write_Test1(){

    #prepare data
    runthis "touch cloud_writeData cloud_readData"
    runthis "dd if=/dev/urandom of=cloud_writeData bs=$config_blockSize count=25"

    ((total_executed++))

    printf "\n\033[1;34mmount and write blocks partially to cloudstore\033[0m\n"
    runthis "$exe_path $accessFile $filesystem_size $blockSize $bucket $mountpoint $filename"

    printf "\n\033[1;34mwrite partial blocks to cloudstore\033[0m\n"
    runthis "dd if=cloud_writeData of=$mountpoint/$mountedfile bs=$(($config_blockSize/2)) count=50"

    unmount_filesystem

    printf "\n\033[1;34mremount file system\033[0m\n"
    runthis "$exe_path $accessFile $filesystem_size $blockSize $bucket $mountpoint $filename"

    printf "\n\033[1;34mread blocks written earlier to cloudstore\033[0m\n"
    runthis "dd of=cloud_readData if=$mountpoint/$mountedfile bs=$(($config_blockSize/2)) count=50"

    printf "\n\033[1;34mcompare cloud_writeData and cloud_readData to confirm if read write worked correctly.files should be same\033[0m\n"
    if diff cloud_writeData cloud_readData  > /dev/null ; then
        printf "\033[1;32m cloud_partial_read_write_Test1 :: PASS\033[0m\n\n"
       ((total_passed++))
    else
        printf "\033[1;31m cloud_partial_read_write_Test1 :: FAIL\033[0m\n\n"
        ((total_failed++))
    fi

    unmount_filesystem

	rm -f cloud_writeData cloud_readData
    printf "\033[1;34merase all blocks\033[0m\n"
    runthis "$exe_path $accessFile $filesystem_size $blockSize $bucket $erase $force $filename"
}

#This test tries to write random data 25 blocks of configured block size to cloud store mounted with readOnly flag. Reads back 50 blocks(partial data) and compares if done correctly
cloud_partial_read_write_Test2(){

    #prepare data
    runthis "touch cloud_writeData cloud_readData"
    runthis "dd if=/dev/urandom of=cloud_writeData bs=$config_blockSize count=25"

    ((total_executed++))

    printf "\n\033[1;34mmount with readOnly flag and write blocks to cloudstore\033[0m\n"
    runthis "$exe_path $accessFile $filesystem_size $blockSize $bucket $mountpoint $filename $readOnly"

    printf "\n\033[1;34mwrite blocks to cloudstore\033[0m\n"
    runthis "dd if=cloud_writeData of=$mountpoint/$mountedfile bs=$(($config_blockSize/2)) count=50"

    unmount_filesystem

    printf "\n\033[1;34mremount file system with readOnly flag \033[0m\n"
    runthis "$exe_path $accessFile $filesystem_size $blockSize $bucket $mountpoint $filename $readOnly"

    printf "\n\033[1;34mread blocks written earlier to cloudstore\033[0m\n"
    runthis "dd of=cloud_readData if=$mountpoint/$mountedfile bs=$(($config_blockSize/2)) count=50"

    printf "\n\033[1;34mcompare cloud_writeData and cloud_readData to confirm if read write worked correctly.files should be different\033[0m\n"
    if diff cloud_writeData cloud_readData  > /dev/null ; then
        printf "\033[1;31m cloud_partial_read_write_Test2 :: FAIL\033[0m\n\n"
       ((total_failed++))
    else
        printf "\033[1;32m cloud_partial_read_write_Test2 :: PASS\033[0m\n\n"
        ((total_passed++))
    fi

    unmount_filesystem

	rm -f cloud_writeData cloud_readData
    printf "\033[1;34merase all blocks\033[0m\n"
    runthis "$exe_path $accessFile $filesystem_size $blockSize $bucket $erase $force $filename"
}

#This test writes random data 25 blocks of configured block size to cloud store, deletes 10 blocks. Reads back 25 blocks of data and compares if done correctly - partial IO
cloud_partial_read_write_Test3(){

    #prepare data
    runthis "touch cloud_writeData cloud_readData"
    runthis "dd if=/dev/urandom of=cloud_writeData bs=$config_blockSize count=25"

    ((total_executed++))

    printf "\n\033[1;34mmount and write blocks to cloudstore\033[0m\n"
    runthis "$exe_path $accessFile $filesystem_size $blockSize $bucket $mountpoint $filename"

    printf "\n\033[1;34mwrite blocks to cloudstore\033[0m\n"
    runthis "dd if=cloud_writeData of=$mountpoint/$mountedfile bs=$(($config_blockSize/2)) count=50"

    unmount_filesystem

    printf "\n\033[1;34mremount file system\033[0m\n"
    runthis "$exe_path $accessFile $filesystem_size $blockSize $bucket $mountpoint $filename"

    printf "\n\033[1;34mwrite zero blocks to cloudstore/ delete blocks\033[0m\n"
    runthis "dd if=/dev/zero of=$mountpoint/$mountedfile bs=$(($config_blockSize/2)) count=20"
	
	unmount_filesystem

    printf "\n\033[1;34mremount file system\033[0m\n"
    runthis "$exe_path $accessFile $filesystem_size $blockSize $bucket $mountpoint $filename"
	
	printf "\n\033[1;34mread blocks written earlier to cloudstore\033[0m\n"
    runthis "dd of=cloud_readData if=$mountpoint/$mountedfile bs=$(($config_blockSize/2)) count=50"
	
    printf "\n\033[1;34mcompare cloud_writeData and cloud_readData to confirm if read write worked correctly.files should be different\033[0m\n"
    if diff cloud_writeData cloud_readData  > /dev/null ; then
        printf "\033[1;31m cloud_partial_read_write_Test3 :: FAIL\033[0m\n\n"
       ((total_failed++))
    else
        printf "\033[1;32m cloud_partial_read_write_Test3 :: PASS\033[0m\n\n"
        ((total_passed++))
    fi

    unmount_filesystem

	rm -f cloud_writeData cloud_readData
    printf "\033[1;34merase all blocks\033[0m\n"
    runthis "$exe_path $accessFile $filesystem_size $blockSize $bucket $erase $force $filename"
}

###################################################################################################################################
######                                       Test cases for local store                                                     #######
###################################################################################################################################

#function to unmount file system
unmount_filesystem(){
    printf "\033[1;34munmount file system\033[0m\n"
    runthis "umount $mountpoint"

    printf "\033[1;34mwaiting for cloudbacker to exit\033[0m\n"
    ps axho comm| grep cloudbacker > /dev/null
    result=$?
    while [ "${result}" -eq "0" ]; do
        sleep 1
        ps axho comm | grep cloudbacker > /dev/null
        result=$?
    done
    printf "\033[1;34munmount done\033[0m\n"
}

#Test invalid localstore path
invalid_localStore_path_Test1(){
    ((total_executed++))
    runthis "$exe_path $accessFile $filesystem_size $blockSize $bucket $mountpoint --localStore=invalid/path $filename"
    if [ $? -ne 0 ]; then
        printf "\033[1;32m invalid_localStore_path_Test1 :: PASS\033[0m\n\n"
        ((total_passed++))
    else
        printf "\033[1;31m invalid_localStore_path_Test1 :: FAIL\033[0m\n\n"
        ((total_failed++))
    fi
}

#Test invalid localstore path
invalid_localStore_path_Test2(){
    ((total_executed++))
    runthis "$exe_path $accessFile $filesystem_size $blockSize $bucket $mountpoint --localStore=$mountedfile $filename"
    if [ $? -ne 0 ]; then
        printf "\033[1;32m invalid_localStore_path_Test2 :: PASS\033[0m\n\n"
        ((total_passed++))
    else
        printf "\033[1;31m invalid_localStore_path_Test2 :: FAIL\033[0m\n\n"
       ((total_failed++))
    fi
}

#Test with empty localstore path
invalid_localStore_path_Test3(){
    ((total_executed++))
    runthis "$exe_path $accessFile $filesystem_size $blockSize $bucket $mountpoint --localStore= $filename"
    if [ $? -ne 0 ]; then
        printf "\033[1;32m invalid_localStore_path_Test3 :: PASS\033[0m\n\n"
        ((total_passed++))
    else
        printf "\033[1;31m invalid_localStore_path_Test3 :: FAIL\033[0m\n\n"
       ((total_failed++))
    fi
}

#Test with valid path, but not a block device as localstore argument parameter
invalid_localStore_path_Test4(){
    ((total_executed++))
    runthis "$exe_path $accessFile $filesystem_size $blockSize $bucket $mountpoint --localStore=/ $filename"
    if [ $? -ne 0 ]; then
        printf "\033[1;32m invalid_localStore_path_Test3 :: PASS\033[0m\n\n"
        ((total_passed++))
    else
        printf "\033[1;31m invalid_localStore_path_Test3 :: FAIL\033[0m\n\n"
        ((total_failed++))
    fi

    empty_block_device    
}

#Test by mounting first without any prefix and later try mounting with some valid prefix, with localstore argument
invalid_localStore_prefix_Test1(){
    ((total_executed++))
    runthis "$exe_path $accessFile $filesystem_size $blockSize $bucket $mountpoint $localStore $filename"
    if [ $? -eq 0 ]; then
        unmount_filesystem
        printf "\n\033[1;34mmount with some prefix\033[0m\n"
        runthis "$exe_path $accessFile $filesystem_size $blockSize $bucket $mountpoint $localStore --prefix=xyz $filename"
         if [ $? -ne 0 ]; then
             printf "\033[1;32m invalid_localStore_prefix_Test1 :: PASS\033[0m\n\n"
             ((total_passed++))
         else
             unmount_filesystem
             printf "\033[1;31m invalid_localStore_prefix_Test1 :: FAIL\033[0m\n\n"
             ((total_failed++))
         fi
    else
        unmount_filesystem
        printf "\033[1;31m invalid_localStore_prefix_Test1 :: FAIL\033[0m\n\n"
        ((total_failed++))
    fi

    printf "\033[1;34merase from bucket with prefix\033[0m\n"
    runthis "$exe_path $accessFile $filesystem_size $blockSize $bucket $erase $force $localStore --prefix=xyz $filename"
    runthis "$exe_path $accessFile $filesystem_size $blockSize $bucket $erase $force $localStore $filename"

    empty_block_device
}

#Test by mounting first with prefix=abc and later try mounting with prefix=xyz, with localstore argument
invalid_localStore_prefix_Test2(){
    ((total_executed++))
    runthis "$exe_path $accessFile $filesystem_size $blockSize $bucket $mountpoint $localStore --prefix=abc $filename"
    if [ $? -eq 0 ]; then
        unmount_filesystem
        printf "\n\033[1;34mmount with other prefix\033[0m\n"
        runthis "$exe_path $accessFile $filesystem_size $blockSize $bucket $mountpoint $localStore --prefix=xyz $filename"
         if [ $? -ne 0 ]; then
             printf "\033[1;32m invalid_localStore_prefix_Test2 :: PASS\033[0m\n\n"
             ((total_passed++))
         else
             unmount_filesystem
             printf "\033[1;31m invalid_localStore_prefix_Test2 :: FAIL\033[0m\n\n"
             ((total_failed++))
         fi
    else
        unmount_filesystem
        printf "\033[1;31m invalid_localStore_prefix_Test2 :: FAIL\033[0m\n\n"
        ((total_failed++))
    fi

    printf "\033[1;34merase from bucket with prefix\033[0m\n"
    runthis "$exe_path $accessFile $filesystem_size $blockSize $bucket $erase $force $localStore --prefix=abc $filename"
    runthis "$exe_path $accessFile $filesystem_size $blockSize $bucket $erase $force $localStore --prefix=xyz $filename"

    empty_block_device    
}

#Test by mounting first with prefix=abc and later try mounting without prefix, with localstore argument
invalid_localStore_prefix_Test3(){
    ((total_executed++))
    runthis "$exe_path $accessFile $filesystem_size $blockSize $bucket $mountpoint $localStore --prefix=abc $filename"
    if [ $? -eq 0 ]; then
        unmount_filesystem
        printf "\n\033[1;34mmount with empty prefix\033[0m\n"
        runthis "$exe_path $accessFile $filesystem_size $blockSize $bucket $mountpoint $localStore $filename"
         if [ $? -ne 0 ]; then
             printf "\033[1;32m invalid_localStore_prefix_Test3 :: PASS\033[0m\n\n"
             ((total_passed++))
         else
             unmount_filesystem
             printf "\033[1;31m invalid_localStore_prefix_Test3 :: FAIL\033[0m\n\n"
             ((total_failed++))
         fi
    else
        printf "\033[1;31m invalid_localStore_prefix_Test3 :: FAIL\033[0m\n\n"
        ((total_failed++))
    fi

    printf "\033[1;34merase from bucket with prefix\033[0m\n"
    runthis "$exe_path $accessFile $filesystem_size $blockSize $bucket $erase $force $localStore --prefix=abc $filename"
    runthis "$exe_path $accessFile $filesystem_size $blockSize $bucket $erase $force $localStore $filename"

    empty_block_device
}

#Test by mounting first with prefix=abcd and later try mounting with prefix=abc, with localstore argument
invalid_localStore_prefix_Test4(){
    ((total_executed++))
    runthis "$exe_path $accessFile $filesystem_size $blockSize $bucket $mountpoint $localStore --prefix=abcd $filename"
    if [ $? -eq 0 ]; then
        unmount_filesystem
        printf "\n\033[1;34mmount with other prefix\033[0m\n"
        runthis "$exe_path $accessFile $filesystem_size $blockSize $bucket $mountpoint $localStore --prefix=abc $filename"
         if [ $? -ne 0 ]; then
             printf "\033[1;32m invalid_localStore_prefix_Test4 :: PASS\033[0m\n\n"
             ((total_passed++))
         else
             unmount_filesystem
             printf "\033[1;31m invalid_localStore_prefix_Test4 :: FAIL\033[0m\n\n"
             ((total_failed++))
         fi
    else
        printf "\033[1;31m invalid_localStore_prefix_Test4 :: FAIL\033[0m\n\n"
        ((total_failed++))
    fi

    printf "\033[1;34merase from bucket with prefix\033[0m\n"
    runthis "$exe_path $accessFile $filesystem_size $blockSize $bucket $erase $force $localStore --prefix=abc $filename"
    runthis "$exe_path $accessFile $filesystem_size $blockSize $bucket $erase $force $localStore --prefix=abcd $filename"

    empty_block_device   
}

#Test by mounting first with prefix=abc and later try mounting with prefix=abcd, with localstore argument
invalid_localStore_prefix_Test5(){
    ((total_executed++))
    runthis "$exe_path $accessFile $filesystem_size $blockSize $bucket $mountpoint $localStore --prefix=abc $filename"
    if [ $? -eq 0 ]; then
        unmount_filesystem
        printf "\n\033[1;34mmount with other prefix\033[0m\n"
        runthis "$exe_path $accessFile $filesystem_size $blockSize $bucket $mountpoint $localStore --prefix=abcd $filename"
         if [ $? -ne 0 ]; then
             printf "\033[1;32m invalid_localStore_prefix_Test5 :: PASS\033[0m\n\n"
             ((total_passed++))
         else
             unmount_filesystem
             printf "\033[1;31m invalid_localStore_prefix_Test5 :: FAIL\033[0m\n\n"
             ((total_failed++))
         fi
    else
        printf "\033[1;31m invalid_localStore_prefix_Test5 :: FAIL\033[0m\n\n"
        ((total_failed++))
    fi

    printf "\033[1;34merase from bucket with prefix\033[0m\n"
    runthis "$exe_path $accessFile $filesystem_size $blockSize $bucket $erase $force $localStore --prefix=abc $filename"
    runthis "$exe_path $accessFile $filesystem_size $blockSize $bucket $erase $force $localStore --prefix=abcd $filename"

    empty_block_device
}

#Test with giving character device for with localstore argument
invalid_localStore_charDevPath_Test1(){
    ((total_executed++))
    runthis "$exe_path $accessFile $filesystem_size $blockSize $bucket $mountpoint --localStore=/dev/urandom $filename"
    if [ $? -ne 0 ]; then
       printf "\033[1;32m invalid_localStore_charDevPath_Test1 :: PASS\033[0m\n\n"
       ((total_passed++))
    else
       printf "\033[1;31m invalid_localStore_charDevPath_Test1 :: FAIL\033[0m\n\n"
       ((total_failed++))
    fi   
    unmount_filesystem
}

#Test with invalid block size with localstore argument
invalid_localStore_blockSize_Test1(){
    ((total_executed++))
    runthis "$exe_path $accessFile $filesystem_size $blockSize $bucket $mountpoint $localStore $filename"
    if [ $? -eq 0 ]; then
        unmount_filesystem
        printf "\n\033[1;34mmount with other blockSize\033[0m\n"
        runthis "$exe_path $accessFile $filesystem_size --blockSize=32K $bucket $mountpoint $localStore $filename"
         if [ $? -ne 0 ]; then
             printf "\033[1;32m invalid_localStore_blockSize_Test1 :: PASS\033[0m\n\n"
             ((total_passed++))
         else
             unmount_filesystem
             printf "\033[1;31m invalid_localStore_blockSize_Test1 :: FAIL\033[0m\n\n"
             ((total_failed++))
         fi
    else
        printf "\033[1;31m invalid_localStore_blockSize_Test1 :: FAIL\033[0m\n\n"
        ((total_failed++))
    fi

    printf "\033[1;34merase from bucket with prefix\033[0m\n"
    runthis "$exe_path $accessFile $filesystem_size $blockSize $bucket $erase $force $localStore $filename"

    empty_block_device    
}

#Test with invalid file system size with localstore argument
invalid_localStore_fileSystemSize_Test1(){
    ((total_executed++))
    runthis "$exe_path $accessFile $filesystem_size $blockSize $bucket $mountpoint $localStore $filename"
    if [ $? -eq 0 ]; then
        unmount_filesystem
        printf "\n\033[1;34mmount with other blockSize\033[0m\n"
        runthis "$exe_path $accessFile --size=13M $blockSize $bucket $mountpoint $localStore $filename"
         if [ $? -ne 0 ]; then
             printf "\033[1;32m invalid_localStore_fileSystemSize_Test1 :: PASS\033[0m\n\n"
             ((total_passed++))
         else
             unmount_filesystem
             printf "\033[1;31m invalid_localStore_fileSystemSize_Test1 :: FAIL\033[0m\n\n"
             ((total_failed++))
         fi
    else
        printf "\033[1;31m invalid_localStore_fileSystemSize_Test1 :: FAIL\033[0m\n\n"
        ((total_failed++))
    fi

    printf "\033[1;34merase from bucket with prefix\033[0m\n"
    runthis "$exe_path $accessFile $filesystem_size $blockSize $bucket $erase $force $localStore $filename"

    empty_block_device    
}

#Test with invalid encryption with localstore argument
invalid_localStore_encryption_Test1(){
    ((total_executed++))
    runthis "$exe_path $accessFile $filesystem_size $blockSize $bucket $mountpoint $localStore $filename --encrypt --password=abcd"
    if [ $? -eq 0 ]; then
        unmount_filesystem
        printf "\n\033[1;34mmount with other blockSize\033[0m\n"
        runthis "$exe_path $accessFile $filesystem_size $blockSize $bucket $mountpoint $localStore $filename --encrypt=AES-256-CBC --password=abcd"
         if [ $? -ne 0 ]; then
             printf "\033[1;32m invalid_localStore_encryption_Test1 :: PASS\033[0m\n\n"
             ((total_passed++))
         else
             unmount_filesystem
             printf "\033[1;31m invalid_localStore_encryption_Test1 :: FAIL\033[0m\n\n"
             ((total_failed++))
         fi
    else
        printf "\033[1;31m invalid_localStore_encryption_Test1 :: FAIL\033[0m\n\n"
        ((total_failed++))
    fi

    printf "\033[1;34merase from bucket with prefix\033[0m\n"
    runthis "$exe_path $accessFile $filesystem_size $blockSize $bucket $erase $force $localStore $filename --encrypt --password=abcd"

    empty_block_device    
}

#Test with invalid encryption with localstore argument. First mount without encryption and later with encryption
invalid_localStore_encryption_Test2(){
    ((total_executed++))
    runthis "$exe_path $accessFile $filesystem_size $blockSize $bucket $mountpoint $localStore $filename"
    if [ $? -eq 0 ]; then
        unmount_filesystem
        printf "\n\033[1;34mmount with other blockSize\033[0m\n"
        runthis "$exe_path $accessFile $filesystem_size $blockSize $bucket $mountpoint $localStore $filename --encrypt --password=abcd"
         if [ $? -ne 0 ]; then
             printf "\033[1;32m invalid_localStore_encryption_Test2 :: PASS\033[0m\n\n"
             ((total_passed++))
         else
             unmount_filesystem
             printf "\033[1;31m invalid_localStore_encryption_Test2 :: FAIL\033[0m\n\n"
             ((total_failed++))
         fi
    else
        printf "\033[1;31m invalid_localStore_encryption_Test2 :: FAIL\033[0m\n\n"
        ((total_failed++))
    fi

    printf "\033[1;34merase from bucket with prefix\033[0m\n"
    runthis "$exe_path $accessFile $filesystem_size $blockSize $bucket $erase $force $localStore $filename"
    runthis "$exe_path $accessFile $filesystem_size $blockSize $bucket $erase $force $localStore $filename --encrypt --password=abcd"

    empty_block_device    
}

#Test with invalid encryption with localstore argument. First mount with encryption and default compression level and later with encryption but different compression level
invalid_localStore_encrypt_compress_Test1(){
    ((total_executed++))
    runthis "$exe_path $accessFile $filesystem_size $blockSize $bucket $mountpoint $localStore $filename --encrypt --compress --password=abcd"
    if [ $? -eq 0 ]; then
        unmount_filesystem
        printf "\n\033[1;34mmount with other blockSize\033[0m\n"
        runthis "$exe_path $accessFile $filesystem_size $blockSize $bucket $mountpoint $localStore $filename --encrypt --compress=2 --password=abcd"
         if [ $? -ne 0 ]; then
             printf "\033[1;32m invalid_localStore_encrypt_compress_Test1 :: PASS\033[0m\n\n"
             ((total_passed++))
         else
             unmount_filesystem
             printf "\033[1;31m invalid_localStore_encrypt_compress_Test1 :: FAIL\033[0m\n\n"
             ((total_failed++))
         fi
    else
        printf "\033[1;31m invalid_localStore_encrypt_compress_Test1 :: FAIL\033[0m\n\n"
        ((total_failed++))
    fi

    printf "\033[1;34merase from bucket with prefix\033[0m\n"
    runthis "$exe_path $accessFile $filesystem_size $blockSize $bucket $erase $force $localStore $filename --encrypt --compress --password=abcd"
    runthis "$exe_path $accessFile $filesystem_size $blockSize $bucket $erase $force $localStore $filename --encrypt --compress=2 --password=abcd"

    empty_block_device    
}

#Test with invalid encryption with localstore argument. First mount with encryption and compression level=2 and later with encryption but compression level=1
invalid_localStore_encrypt_compress_Test2(){
    ((total_executed++))
    runthis "$exe_path $accessFile $filesystem_size $blockSize $bucket $mountpoint $localStore $filename --encrypt --compress=2 --password=abcd"
    if [ $? -eq 0 ]; then
        unmount_filesystem
        printf "\n\033[1;34mmount with other blockSize\033[0m\n"
        runthis "$exe_path $accessFile $filesystem_size $blockSize $bucket $mountpoint $localStore $filename --encrypt --compress=1 --password=abcd"
         if [ $? -ne 0 ]; then
             printf "\033[1;32m invalid_localStore_encrypt_compress_Test2 :: PASS\033[0m\n\n"
             ((total_passed++))
         else
             unmount_filesystem
             printf "\033[1;31m invalid_localStore_encrypt_compress_Test2 :: FAIL\033[0m\n\n"
             ((total_failed++))
         fi
    else
        printf "\033[1;31m invalid_localStore_encrypt_compress_Test2 :: FAIL\033[0m\n\n"
        ((total_failed++))
    fi

    printf "\033[1;34merase from bucket with prefix\033[0m\n"
    runthis "$exe_path $accessFile $filesystem_size $blockSize $bucket $erase $force $localStore $filename --encrypt --compress=1 --password=abcd"
    runthis "$exe_path $accessFile $filesystem_size $blockSize $bucket $erase $force $localStore $filename --encrypt --compress=2 --password=abcd"

    empty_block_device    
}

#Test with invalid nameHash with localStore argument
invalid_localStore_nameHash_Test1(){
    ((total_executed++))
    runthis "$exe_path $accessFile $filesystem_size $blockSize $bucket $mountpoint $localStore $filename --nameHash"
    if [ $? -eq 0 ]; then
        unmount_filesystem
        printf "\n\033[1;34mmount with other blockSize -  through auto detection\033[0m\n"
        runthis "$exe_path $accessFile $filesystem_size $blockSize $bucket $mountpoint $localStore $filename"
         if [ $? -eq 0 ]; then
             unmount_filesystem
             printf "\033[1;32m invalid_localStore_nameHash_Test1 :: PASS\033[0m\n\n"
             ((total_passed++))
         else
             unmount_filesystem
             printf "\033[1;31m invalid_localStore_nameHash_Test1 :: FAIL\033[0m\n\n"
             ((total_failed++))
         fi
    else
        printf "\033[1;31m invalid_localStore_nameHash_Test1 :: FAIL\033[0m\n\n"
        ((total_failed++))
    fi

    printf "\033[1;34merase from bucket with prefix\033[0m\n"
    runthis "$exe_path $accessFile $filesystem_size $blockSize $bucket $erase $force $localStore $filename --nameHash"
    runthis "$exe_path $accessFile $filesystem_size $blockSize $bucket $erase $force $localStore $filename"
    
    empty_block_device
}

#Test with giving file system size greater than the block device size, but not multiple of blockSize value with localstore argument
invalid_localStore_filesystemsize_Test1(){
    ((total_executed++))
    runthis "$exe_path $accessFile --size=$(($bd_size+1)) $blockSize $bucket $mountpoint $localStore $filename"
    if [ $? -ne 0 ]; then
       printf "\033[1;32m invalid_localStore_filesystemsize_Test1 :: PASS\033[0m\n\n"
       ((total_passed++))
    else
       printf "\033[1;31m invalid_localStore_filesystemsize_Test1 :: FAIL\033[0m\n\n"
       ((total_failed++))
    fi   

    empty_block_device
}

#Test with giving file system size greater than the block device size, but multiple of blockSize value with localstore argument
invalid_localStore_filesystemsize_Test2(){
    ((total_executed++))
    runthis "$exe_path $accessFile --size=$(($bd_size*2)) $blockSize $bucket $mountpoint $localStore $filename"
    if [ $? -ne 0 ]; then
       printf "\033[1;32m invalid_localStore_filesystemsize_Test2 :: PASS\033[0m\n\n"
       ((total_passed++))
    else
       printf "\033[1;31m invalid_localStore_filesystemsize_Test2 :: FAIL\033[0m\n\n"
       ((total_failed++))
    fi   
  
    printf "\033[1;34merase from bucket with prefix\033[0m\n"
    runthis "$exe_path $accessFile --size=$(($bd_size*2)) $blockSize $bucket $erase $force $localStore $filename"

    empty_block_device
}

#Test with giving block size, but not a block device compatible blockSize value with localstore argument
invalid_localStore_blocksize_Test1(){
    ((total_executed++))
    runthis "$exe_path $accessFile $filesystem_size --blockSize=$(($bd_blockSize+1)) $bucket $mountpoint $localStore $filename"
    if [ $? -ne 0 ]; then
       printf "\033[1;32m invalid_localStore_blocksize_Test1 :: PASS\033[0m\n\n"
       ((total_passed++))
    else
       printf "\033[1;31m invalid_localStore_blocksize_Test1 :: FAIL\033[0m\n\n"
       ((total_failed++))
    fi
    
    empty_block_device
}

#Test with giving block size greater than the block device size, but multiple of blockSize value with localstore argument
invalid_localStore_blocksize_Test2(){
    ((total_executed++))
    runthis "$exe_path $accessFile --size=$(($bd_size*2)) --blockSize=$(($bd_blockSize*$bd_blockSize)) $bucket $mountpoint $localStore $filename"
    if [ $? -ne 0 ]; then
       printf "\033[1;32m invalid_localStore_blocksize_Test2 :: PASS\033[0m\n\n"
       ((total_passed++))
    else
       printf "\033[1;31m invalid_localStore_blocksize_Test2 :: FAIL\033[0m\n\n"
       ((total_failed++))
    fi

    printf "\033[1;34merase from bucket with prefix\033[0m\n"
    runthis "$exe_path $accessFile --size=$(($bd_size*2)) --blockSize=$(($bd_blockSize*$bd_blockSize)) $bucket $erase $force $localStore $filename"

    empty_block_device
}

#This test writes random data 50 blocks of BS=64K to local store. Reads back the written data and compares if done correctly
localStore_read_write_Test1(){

    #prepare data
    runthis "touch writeData"
    runthis "dd if=/dev/urandom of=writeData bs=64K count=50"

    ((total_executed++))

    printf "\n\033[1;34mmount and write blocks to localstore\033[0m\n"
    runthis "$exe_path $accessFile $filesystem_size --blockSize=64K $bucket $mountpoint $localStore $filename"

    printf "\n\033[1;34mwrite blocks to localstore\033[0m\n"
    runthis "dd if=writeData of=$mountpoint/$mountedfile bs=65536 count=50"

    unmount_filesystem

    printf "\n\033[1;34mremount file system\033[0m\n"
    runthis "$exe_path $accessFile $filesystem_size --blockSize=64K $bucket $mountpoint $localStore $filename"

    printf "\n\033[1;34mread blocks written earlier to localstore\033[0m\n"
    runthis "dd of=readData if=$mountpoint/$mountedfile bs=65536 count=50"

    printf "\n\033[1;34mcompare writeData and readData to confirm if read write worked correctly.\033[0m\n"
    if diff writeData readData  > /dev/null ; then
        printf "\033[1;32m localStore_read_write_Test1 :: PASS\033[0m\n\n"
       ((total_passed++))
    else
        printf "\033[1;31m localStore_read_write_Test1 :: FAIL\033[0m\n\n"
        ((total_failed++))
    fi

    unmount_filesystem

    printf "\033[1;34merase all blocks\033[0m\n"
    runthis "$exe_path $accessFile $filesystem_size --blockSize=64K $bucket $localStore $erase $force $filename"
   
    empty_block_device
}

#This test writes random data 25 blocks of BS=64K to local store. Reads back 50 blocks of data and compares if done correctly
localStore_read_write_Test2(){

    #prepare data
    runthis "touch writeData"
    runthis "dd if=/dev/urandom of=writeData bs=64K count=25"

    ((total_executed++))

    printf "\n\033[1;34mmount and write blocks to localstore\033[0m\n"
    runthis "$exe_path $accessFile $filesystem_size --blockSize=64K $bucket $mountpoint $localStore $filename"

    printf "\n\033[1;34mwrite blocks to localstore\033[0m\n"
    runthis "dd if=writeData of=$mountpoint/$mountedfile bs=65536 count=25"

    unmount_filesystem

    printf "\n\033[1;34mremount file system\033[0m\n"
    runthis "$exe_path $accessFile $filesystem_size --blockSize=64K $bucket $mountpoint $localStore $filename"

    printf "\n\033[1;34mread blocks written earlier to localstore\033[0m\n"
    runthis "dd of=readData if=$mountpoint/$mountedfile bs=65536 count=50"

    printf "\n\033[1;34mcompare writeData and readData to confirm if read write worked correctly.files should be different\033[0m\n"
    if diff writeData readData  > /dev/null ; then
        printf "\033[1;31m localStore_read_write_Test2 :: FAIL\033[0m\n\n"
       ((total_failed++))
    else
        printf "\033[1;32m localStore_read_write_Test2 :: PASS\033[0m\n\n"
        ((total_passed++))
    fi

    unmount_filesystem

    printf "\033[1;34merase all blocks\033[0m\n"
    runthis "$exe_path $accessFile $filesystem_size --blockSize=64K $bucket $localStore $erase $force $filename"

    empty_block_device
}

#prints the test execution summary
print_TestExecution_Summary(){

  printf "\n\033[1;37m #########################\033[0m\033[1;38m  Test Execution Summary \033[0m\033[1;37m  ##########################\033[0m\n\n"
  printf "\n\033[1;34m       Total test cases executed     =     $total_executed \033[0m"
  printf "\n\033[1;32m       Test cases passed             =     $total_passed \033[0m"
  printf "\n\033[1;31m       Test cases failed             =     $total_failed \033[0m\n"
  printf "\n\n\033[1;37m ###############################################################################\033[0m\n"

}

#invoke test functions for execution

#run tests - invalid bucket name
invalid_bucketName_Test1
invalid_bucketName_Test2
invalid_bucketName_Test3
invalid_bucketName_Test4
invalid_bucketName_Test5
invalid_bucketName_Test6
invalid_bucketName_Test7
invalid_bucketName_Test8

#run tests - invalid accessFile argument
invalid_accessFile_Test1
invalid_accessFile_Test2

#run tests - invalid accessId and/or accesskey argument
invalid_accessId_Key_Test1
invalid_accessId_Key_Test2

#run tests - invalid accessType argument
invalid_accessType_Test1

#run tests - invalid authVersion argument
invalid_authVersion_Test1
invalid_authVersion_Test2

#run tests - invalid baseURL argument
invalid_baseURL_Test1
invalid_baseURL_Test2
invalid_baseURL_Test3
invalid_baseURL_Test4

#run tests - invalid blockSize argument
invalid_blockSize_Test1
invalid_blockSize_Test2

#run tests - invalid fileMode argument
invalid_filemode_Test1
invalid_filemode_Test2
invalid_filemode_Test3

#run tests - invalid fileName argument
invalid_filename_Test1
invalid_filename_Test2

#run tests - invalid stats fileName argument
invalid_stats_filename_Test1
invalid_stats_filename_Test2

#run tests - invalid region argument
invalid_region_Test1
invalid_region_Test2
invalid_region_Test3

#run tests - invalid storageClass argument
invalid_storageClass_Test1
invalid_storageClass_Test2
invalid_storageClass_Test3
invalid_storageClass_Test4

#run tests - invalid size, blockSize arguments
invalid_filesize_Test1
invalid_filesize_Test2
invalid_blocksize_Test1

#run tests -meta data handling
invalid_metadata_filesize_Test1
invalid_metadata_blockSize_Test1
autoDetect_metadata_blockSize_Test1
autoDetect_metadata_nameHash_Test1
autoDetect_metadata_nameHash_Test2
autoDetect_metadata_encryption_Test1
autoDetect_metadata_encryption_Test2
autoDetect_metadata_encryption_Test3
autoDetect_metadata_encryption_Test4
autoDetect_metadata_compress_Test1
autoDetect_metadata_compress_Test2
autoDetect_metadata_compress_Test3

#run tests - IO operations on cloud
cloud_read_write_Test1
cloud_read_write_Test2
cloud_read_write_Test3

#run tests - partial IO operations on cloud
cloud_partial_read_write_Test1
cloud_partial_read_write_Test2
cloud_partial_read_write_Test3

#run tests - invalid localStore argument
invalid_localStore_path_Test1
invalid_localStore_path_Test2
invalid_localStore_path_Test3
invalid_localStore_path_Test4
invalid_localStore_charDevPath_Test1

#run tests - invalid blockSize
invalid_localStore_blockSize_Test1

#run tests - invalid file system Size
invalid_localStore_fileSystemSize_Test1

#run tests - encryption with localstore argument
invalid_localStore_encryption_Test1
invalid_localStore_encryption_Test2
invalid_localStore_encrypt_compress_Test1
invalid_localStore_encrypt_compress_Test2

#run tests - nameHash flag with localstore argument
invalid_localStore_nameHash_Test1

#run tests - invalid prefix with localStore argument
invalid_localStore_prefix_Test1
invalid_localStore_prefix_Test2
invalid_localStore_prefix_Test3
invalid_localStore_prefix_Test4
invalid_localStore_prefix_Test5

#run tests - invalid file system size with localStore argument
invalid_localStore_filesystemsize_Test1
invalid_localStore_filesystemsize_Test2

#run tests - invalid block size with localStore argument
invalid_localStore_blocksize_Test1
invalid_localStore_blocksize_Test2

#run tests - local store read write of blocks
localStore_read_write_Test1
localStore_read_write_Test2

#completed test case execution, Now go and print test execution summary
print_TestExecution_Summary

printf "\n\033[1;36m  Done. Thank you \033[0m\n\n"
