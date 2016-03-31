
time bin/tls-check-parallel.pl --files=t/more-testdomains/dummy-de-domains-1000-a.csv --temp_out_interval=200 --my_hostname=wurzelgnom2.a-blast.org --outfile=result/test-wurzelgnom-de1000a-fixed-1.csv --jobs=100 --checks=Web --checks=CipherStrength
date
mv logs/ result/logs-test-wurzelgnom-de1000a-fixed-1/ ; mkdir logs

echo
echo ==============================================
echo

time bin/tls-check-parallel.pl --files=t/more-testdomains/dummy-de-domains-1000-a.csv --temp_out_interval=200 --my_hostname=wurzelgnom2.a-blast.org --outfile=result/test-wurzelgnom-de1000a-fixed-2.csv --jobs=100 --checks=Web --checks=CipherStrength
date
mv logs/ result/logs-test-wurzelgnom-de1000a-fixed-2/ ; mkdir logs

echo
echo ==============================================
echo

time bin/tls-check-parallel.pl --files=t/more-testdomains/dummy-de-domains-1000-a.csv --temp_out_interval=200 --my_hostname=wurzelgnom2.a-blast.org --outfile=result/test-wurzelgnom-de1000a-fixed-3.csv --jobs=100 --checks=Web --checks=CipherStrength
date
mv logs/ result/logs-test-wurzelgnom-de1000a-fixed-3/ ; mkdir logs


echo
echo ==============================================
echo

echo
echo ==============================================
echo




# Alle sind:
# DNS Web Mail Dummy CipherStrength MailCipherStrength AgeDE Heartbleed CipherStrengthOnlyValidCerts

date
time bin/tls-check-parallel.pl --files=tmp/Alle\ mit\ Internetadresse\ Final_2015.11.csv --outfile=tmp/result-v45.csv --temp_out_interval=250 --jobs=50 --checks="DNS Web Mail Dummy CipherStrength MailCipherStrength AgeDE CipherStrengthOnlyValidCerts"
date


# 
# 
# 
# 
# time bin/tls-check-parallel.pl --files=t/more-testdomains/dummy-de-domains-1000-b.csv --temp_out_interval=100 --my_hostname=wurzelgnom2.a-blast.org --outfile=result/test-wurzelgnom-de1000b-1.txt --jobs=20 --checks=Web --checks=CipherStrength
# date
# mv logs/ result/logs-test-wurzelgnom-de1000b-1/ ; mkdir logs
# 
# echo
# echo ==============================================
# echo
# 
# time bin/tls-check-parallel.pl --files=t/more-testdomains/dummy-de-domains-1000-b.csv --temp_out_interval=100 --my_hostname=wurzelgnom2.a-blast.org --outfile=result/test-wurzelgnom-de1000b-2.txt --jobs=20 --checks=Web --checks=CipherStrength
# date
# mv logs/ result/logs-test-wurzelgnom-de1000b-2/ ; mkdir logs
# 
# echo
# echo ==============================================
# echo
# 
# time bin/tls-check-parallel.pl --files=t/more-testdomains/dummy-de-domains-1000-b.csv --temp_out_interval=100 --my_hostname=wurzelgnom2.a-blast.org --outfile=result/test-wurzelgnom-de1000b-3.txt --jobs=20 --checks=Web --checks=CipherStrength
# date
# mv logs/ result/logs-test-wurzelgnom-de1000b-3/ ; mkdir logs
# 
# 
# 
# 
# 
# 
# echo
# echo ==============================================
# echo
# 
# echo
# echo ==============================================
# echo
# 
# 
# 
# 
# 
# 
# time bin/tls-check-parallel.pl --files=t/more-testdomains/dummy-de-domains-1000-c.csv --temp_out_interval=100 --my_hostname=wurzelgnom2.a-blast.org --outfile=result/test-wurzelgnom-de1000c-full-1.txt --jobs=30 
# date
# mv logs/ result/logs-test-wurzelgnom-de1000c-1/ ; mkdir logs
# 
# echo
# echo ==============================================
# echo
# 
# time bin/tls-check-parallel.pl --files=t/more-testdomains/dummy-de-domains-1000-c.csv --temp_out_interval=100 --my_hostname=wurzelgnom2.a-blast.org --outfile=result/test-wurzelgnom-de1000c-full-2.txt --jobs=30 
# date
# mv logs/ result/logs-test-wurzelgnom-de1000c-2/ ; mkdir logs
# 
# echo
# echo ==============================================
# echo
# 
# time bin/tls-check-parallel.pl --files=t/more-testdomains/dummy-de-domains-1000-c.csv --temp_out_interval=100 --my_hostname=wurzelgnom2.a-blast.org --outfile=result/test-wurzelgnom-de1000c-full-3.txt --jobs=30 
# date
# mv logs/ result/logs-test-wurzelgnom-de1000c-3/ ; mkdir logs
# 
# 
# 
# 




