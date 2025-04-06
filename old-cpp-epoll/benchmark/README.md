## Convert from raw output to data files

Something like:

```
grep ^'User time'  1k_to_10m_step_20k_rpi_sendfile.txt \
  | awk 'BEGIN{N=1} {print N " " $3; N+=20}' \
  > more_sendfile_user.txt
```
