@echo off
echo ---
echo ---Curl down the pipeline2detailedreport converter
echo ---
curl -sSO https://raw.githubusercontent.com/jphillips-vc/pipeline2detailedreport/master/detailedreport.py
echo ---
echo ---Curl the latest version of Veracode's Pipeline Scan
echo ---
mkdir veracode
curl -sSO https://downloads.veracode.com/securityscan/pipeline-scan-LATEST.zip
echo ---
echo ---Unzip Veracode Pipeline Scan
echo ---
"C:\Program Files\7-Zip\7z" e pipeline-scan-LATEST.zip
echo ---
echo ---run the pipeline scan
echo ---
cd ..
java -jar ./veracode/pipeline-scan.jar -f %1
echo ---
echo ---convert the results.json file to pipeline2detailedreport
echo ---
python detailedreport.py
echo ---
echo ---clean up
echo ---
cd ./veracode
del /q pipeline-scan.jar
del /Q pipeline-scan-LATEST.zip
del /Q README.md
cd ..
rmdir ./veracode
del /Q detailedreport.py
echo ---done
echo on
