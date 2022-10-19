#!/bin/bash
### api.txt content like https://www.baidu.com/xxx.html
dir=`dirname $0`
file=${dir}/api.txt
for url in `cat $file`
do
host=`echo $url |awk -F/ '{print $3}'`
prefix=`echo $url |awk -F/ '{print $NF}'`
curl -s $url > /tmp/${prefix}-0.txt
hosts=('host1' 'host2')
  for i in {0..3}
  do
    if [ $i -gt 0 ];then
    eval curl -s $url --resolve ${host}:443:${hosts[$i]} > /tmp/${prefix}-${i}.txt
    fi
    eval md5${i}=`md5sum /tmp/${prefix}-${i}.txt|awk '{print $1}'`
    eval md5mid=md5${i}
    eval md5=$(echo \$${md5mid})
    #echo  ${md5}
   # exit
    if [ $i -gt 0 ];then
    if [ "${md50}" != "${md5}" ] ;then
      echo $url ${md50} ${md5}  ${hosts[$i]} >> /tmp/cdn_error.txt
      echo $url ${md50} ${md5}  ${hosts[$i]} 
      #echo 500
      exit 500
    fi
    fi
  done
done
echo 0
