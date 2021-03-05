# watch dog for process wpr
crawl_date=$1
cd "${0%/*}" # cd folder of this script
while true
do
	pgrep -x wpr > /dev/null
	if [[ $? -gt 0 ]]
	then 
		now=$(date)
		printf "%s :: Run wpr.go convert\n" "$now"
		go run src/wpr.go convert --har_file=/tmp/HttpArchive/$crawl_date
	fi
	sleep 10
done
