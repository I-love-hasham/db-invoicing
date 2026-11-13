# Inside the container the app listens on 8080; docker-compose publishes it
# on the host as 127.0.0.1:8080 only, so nothing outside the server can reach it.
bind = "0.0.0.0:8080"
workers = 2
threads = 2
preload_app = True          # create/upgrade the databases once at start
worker_tmp_dir = "/dev/shm"  # root filesystem is read-only
timeout = 60
accesslog = "-"
errorlog = "-"
loglevel = "info"
# Access log: no query strings or cookies (nothing secret is ever in a URL anyway).
access_log_format = '%({cf-connecting-ip}i)s "%(m)s %(U)s" %(s)s %(b)s %(D)sus'
limit_request_line = 4094
limit_request_fields = 100
