#!/usr/bin/env gnuplot

set terminal pngcairo size 1280,720
set output "writev_sendfile_cpu.png"

set ylabel "CPU ms per MB"
set xlabel "GET size in MB"

# $2 / n / mb * ms
#   $2 = total CPU time in seconds
#   n  = number of requests
#   mb = per request size in mb
#   ms = 1000

# 100 requests sent per sample
plot \
     'writev_user.dat'     using 1:($2/100/$1*1000) w l title "writev() user", \
     'writev_system.dat'   using 1:($2/100/$1*1000) w l title "writev() system", \
     'sendfile_user.dat'   using 1:($2/100/$1*1000) w l title "sendfile() user", \
     'sendfile_system.dat' using 1:($2/100/$1*1000) w l title "sendfile() system"

set output "writev_sendfile_cpu_zoomed.png"
set ylabel "CPU ms per MB"
set xlabel "GET size in MB"

# 1000 requests per sample.
# Then ms and number of requests cancel out.
plot [0:9] [0:3] \
     'more_writev_user.txt'     using ($1/1000):($2/$1*1000) w l title "writev() user", \
     'more_writev_system.txt'   using ($1/1000):($2/$1*1000) w l title "writev() system", \
     'more_sendfile_user.txt'   using ($1/1000):($2/$1*1000) w l title "sendfile() user", \
     'more_sendfile_system.txt' using ($1/1000):($2/$1*1000) w l title "sendfile() system"
