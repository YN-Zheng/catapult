# watch dog for process wpr


while true
do
	pgrep -x wpr > /dev/null
	if [[ $? -gt 0 ]]
	then 
		now=$(date)
		printf "%s :: Process 'wpr' not found, restart\n" "$now"
		nohup /home/yongnian/sdk/go1.16/bin/go run src/wpr.go convert --har_file=/home/yongnian/Downloads/Http\ Archive/chrome-Apr_1_2016 &
	fi
	sleep 10
done
