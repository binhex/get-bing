import requests
import urllib3
import configobj
import validate
import argparse
import os
import sys
import socket
import logging
import logging.handlers
import backoff
import json
import schedule
import time
import daemon
import signal
import datetime

urllib3.disable_warnings()  # required to suppress ssl warning for urllib3 (requests uses urllib3)
signal.signal(signal.SIGINT, signal.default_int_handler)  # ensure we correctly handle all keyboard interrupts

# TODO regex for copyright
# TODO looks like hashes do not work, different hashes for same image :-(, maybe look at filename?
# TODO put back startdate thing from metadata, used instead of datenow and pass to downloader function
# TODO look at multiple images per country by specfying the 'num', needs a config.ini entry to define this


def create_config():

    validator = validate.Validator()
    config_obj.validate(validator, copy=True)
    config_obj.filename = config_ini
    config_obj.write()


def app_logging():

    # read log levels
    log_level = config_obj["general"]["log_level"]

    # setup formatting for log messages
    app_formatter = logging.Formatter("%(asctime)s %(threadName)s %(module)s %(funcName)s :: [%(levelname)s] %(message)s")

    # setup logger for app
    app_logger = logging.getLogger("app")

    # add rotating log handler
    app_rotatingfilehandler = logging.handlers.RotatingFileHandler(app_log_file, "a", maxBytes=10485760, backupCount=3, encoding="utf-8")

    # set formatter for app
    app_rotatingfilehandler.setFormatter(app_formatter)

    # add the log message handler to the logger
    app_logger.addHandler(app_rotatingfilehandler)

    # set level of logging from config
    if log_level == "DEBUG":

        app_logger.setLevel(logging.DEBUG)

    elif log_level == "INFO":

        app_logger.setLevel(logging.INFO)

    elif log_level == "WARNING":

        app_logger.setLevel(logging.WARNING)

    elif log_level == "ERROR":

        app_logger.setLevel(logging.ERROR)

    # setup logging to console
    console_streamhandler = logging.StreamHandler()

    # set formatter for console
    console_streamhandler.setFormatter(app_formatter)

    # add handler for formatter to the console
    app_logger.addHandler(console_streamhandler)

    # set level of logging from config
    if log_level == "DEBUG":

        console_streamhandler.setLevel(logging.DEBUG)

    elif log_level == "INFO":

        console_streamhandler.setLevel(logging.INFO)

    elif log_level == "WARNING":

        console_streamhandler.setLevel(logging.WARNING)

    elif log_level == "ERROR":

        console_streamhandler.setLevel(logging.ERROR)

    return {'logger': app_logger, 'handler': app_rotatingfilehandler}


@backoff.on_exception(backoff.expo, (socket.timeout, requests.exceptions.Timeout, requests.exceptions.HTTPError), max_tries=10)
def http_client(**kwargs):

    if kwargs is not None:

        if "url" in kwargs:

            url = kwargs['url']

        else:

            app_logger_instance.warning(u'No URL sent to function, exiting function...')
            return 1, None

        if "user_agent" in kwargs:

            user_agent = kwargs['user_agent']

        else:

            app_logger_instance.warning(u'No User Agent sent to function, exiting function...')
            return 1, None

        if "request_type" in kwargs:

            request_type = kwargs['request_type']

        else:

            app_logger_instance.warning(u'No request type (get/put/post) sent to function, exiting function...')
            return 1, None

        # optional stuff to include
        if "auth" in kwargs:

            auth = kwargs['auth']

        else:

            auth = None

        if "additional_header" in kwargs:

            additional_header = kwargs['additional_header']

        else:

            additional_header = None

        if "data_payload" in kwargs:

            data_payload = kwargs['data_payload']

        else:

            data_payload = None

    else:

        app_logger_instance.warning(u'No keyword args sent to function, exiting function...')
        return 1

    # set connection timeout value (max time to wait for connection)
    connect_timeout = 10.0

    # set read timeout value (max time to wait between each byte)
    read_timeout = 5.0

    # use a session instance to customize how "requests" handles making http requests
    session = requests.Session()

    # set status_code and content to None in case nothing returned
    status_code = None
    content = None

    try:

        # define dict of common arguments for requests
        requests_data_dict = {'url': url, 'timeout': (connect_timeout, read_timeout), 'allow_redirects': True, 'verify': False}

        session.headers = {
            'Accept-encoding': 'gzip',
            'User-Agent': user_agent
        }

        if "additional_header" in kwargs:

            # append to headers dict with additional headers dict
            session.headers.update(additional_header)

        if "auth" in kwargs:

            session.auth = auth

        if request_type == "put":

            # add additional keyword arguments
            requests_data_dict.update({'data': data_payload})

        elif request_type == "post":

            # add additional keyword arguments
            requests_data_dict.update({'data': data_payload})

        # construct class.method from request_type
        request_method = getattr(session, request_type)

        # use keyword argument unpack to convert dict to keyword args
        response = request_method(**requests_data_dict)

        # get status code and content returned
        status_code = response.status_code
        content = response.content

        if status_code == 401:

            app_logger_instance.warning(u"The status code %s indicates unauthorised access for %s, error is %s" % (status_code, url, content))
            raise requests.exceptions.HTTPError

        elif status_code == 404:

            app_logger_instance.warning(u"The status code %s indicates the requested resource could not be found  for %s, error is %s" % (status_code, url, content))
            raise requests.exceptions.HTTPError

        elif status_code == 422:

            app_logger_instance.warning(u"The status code %s indicates a request was well-formed but was unable to be followed due to semantic errors for %s, error is %s" % (status_code, url, content))
            raise requests.exceptions.HTTPError

        elif not 200 <= status_code <= 299:

            app_logger_instance.warning(u"The status code %s indicates an unexpected error for %s, error is %s" % (status_code, url, content))
            raise requests.exceptions.HTTPError

    except requests.exceptions.ConnectTimeout as content:

        # connect timeout occurred
        app_logger_instance.warning(u"Connection timed for URL %s with error %s" % (url, content))
        return 1, status_code, content

    except requests.exceptions.ConnectionError as content:

        # connection error occurred
        app_logger_instance.warning(u"Connection error for URL %s with error %s" % (url, content))
        return 1, status_code, content

    except requests.exceptions.TooManyRedirects as content:

        # too many redirects, bad site or circular redirect
        app_logger_instance.warning(u"Too many retries for URL %s with error %s" % (url, content))
        return 1, status_code, content

    except requests.exceptions.HTTPError:

        # catch http exceptions thrown by requests
        return 1, status_code, content

    except requests.exceptions.RequestException as content:

        # catch any other exceptions thrown by requests
        app_logger_instance.warning(u"Caught other exceptions for URL %s with error %s" % (url, content))
        return 1, status_code, content

    else:

        if 200 <= status_code <= 299:

            app_logger_instance.info(u"The status code %s indicates a successful request for %s" % (status_code, url))
            return 0, status_code, content


def image_url(**kwargs):

    request_type = "get"

    # unpack all keyword args
    if kwargs is not None:

        if "image_json_url" in kwargs:

            image_json_url = kwargs['image_json_url']

        else:

            app_logger_instance.warning(u'No URL sent to function, exiting function...')
            return 1, None, None

        if "base_url" in kwargs:

            base_url = kwargs['base_url']

        else:

            app_logger_instance.warning(u'No base url config value send to function, exiting function...')
            return 1, None, None

        if "image_hash" in kwargs:

            image_hash_config = kwargs['image_hash']

        else:

            app_logger_instance.warning(u'No image hash config value send to function, exiting function...')
            return 1, None, None

        if "image_resolution" in kwargs:

            image_resolution = kwargs['image_resolution']

        else:

            app_logger_instance.warning(u'No image resolution config value send to function, exiting function...')
            return 1, None, None

    else:

        app_logger_instance.warning(u'No keyword args sent to function, exiting function...')
        return 1, None, None

    # download webpage content
    return_code, status_code, content = http_client(url=image_json_url, user_agent=user_agent_chrome, request_type=request_type)

    if return_code == 0:

        try:

            # decode json
            content = json.loads(content)

        except (ValueError, TypeError, KeyError, IndexError):

            app_logger_instance.error(u"Problem loading json from '%s', skipping to next iteration..." % image_json_url)
            return 1, None, None

    else:

        app_logger_instance.error(u"Problem downloading json content from '%s', skipping to new release..." % image_json_url)
        return 1, None, None

    try:

        # get image hash value (used to determine if we already have the image)
        image_hash_web = content['images'][0]['hsh']
        app_logger_instance.info(u"Image hash value from website is '%s'" % image_hash_web)

    except (ValueError, TypeError, KeyError, IndexError):

        app_logger_instance.error(u"Problem parsing json for image hash from '%s', skipping to next iteration..." % image_json_url)
        return 1, None, None

    try:

        # get image url construct
        image_url_base = content['images'][0]['urlbase']
        app_logger_instance.info(u"Image urlbase construct is '%s'" % image_url_base)

    except (ValueError, TypeError, KeyError, IndexError):

        app_logger_instance.error(u"Problem parsing json for image urlbase from '%s', skipping to next iteration..." % image_json_url)
        return 1, None, None

    try:

        # get image copyright (used to get description of image for filename)
        image_copyright_metadata = content['images'][0]['copyright']
        app_logger_instance.info(u"Image copyright is '%s'" % image_copyright_metadata)

    except (ValueError, TypeError, KeyError, IndexError):

        app_logger_instance.error(u"Problem parsing json for image copyright from '%s', skipping to next iteration..." % image_json_url)
        return 1, None, None

    if image_hash_web not in image_hash_config:

        app_logger_instance.info(u"Image hash not found in config.ini, looks like a new image, continuing to download...")

        # construct full url to image
        image_download_url_web = u"%s%s_%s.jpg" % (base_url, image_url_base, image_resolution)
        app_logger_instance.info(u"Image download URL is %s" % image_download_url_web)

        app_logger_instance.info(u"Successfully downloaded image metadata")
        return 0, image_hash_web, image_download_url_web

    else:

        app_logger_instance.info(u"Image hash already in config.ini, looks like we previously downloaded the image, skipping download")
        return 2, None, None


def image_download(**kwargs):

    request_type = "get"

    # unpack all keyword args
    if kwargs is not None:

        if "image_download_url_web" in kwargs:

            image_download_url_web = kwargs['image_download_url_web']

        else:

            app_logger_instance.warning(u'No URL sent to function, exiting function...')
            return 1

        if "image_hash_web" in kwargs:

            image_hash_web = kwargs['image_hash_web']

        else:

            app_logger_instance.warning(u'No image hash web value sent to function, exiting function...')
            return 1

        if "image_country" in kwargs:

            image_country = kwargs['image_country']

        else:

            app_logger_instance.warning(u'No image country config value sent to function, exiting function...')
            return 1

        if "image_preferred_country" in kwargs:

            image_preferred_country = kwargs['image_preferred_country']

        else:

            app_logger_instance.warning(u'No preferred image country config value sent to function, exiting function...')
            return 1

        if "image_dest_dir" in kwargs:

            image_dest_dir = kwargs['image_dest_dir']

        else:

            app_logger_instance.warning(u'No image dest dir config value sent to function, exiting function...')
            return 1

        if "image_dest_file" in kwargs:

            image_dest_file = kwargs['image_dest_file']

        else:

            app_logger_instance.warning(u'No image dest file config value sent to function, exiting function...')
            return 1

        if "image_arch_dir" in kwargs:

            image_arch_dir = kwargs['image_arch_dir']

        else:

            app_logger_instance.warning(u'No image arch dir config value sent to function, exiting function...')
            return 1

    else:

        app_logger_instance.warning(u'No keyword args sent to function, exiting function...')
        return 1

    # download webpage content
    return_code, status_code, content = http_client(url=image_download_url_web, user_agent=user_agent_chrome, request_type=request_type)

    if return_code == 0:

        if image_preferred_country == image_country:

            if not os.path.exists(image_dest_dir):
                os.makedirs(image_dest_dir)

            # construct full path and filename for wallpaper
            image_dest_path = os.path.join(image_dest_dir, image_dest_file)
            app_logger_instance.info(u"Location to save the wallpaper image file is %s" % image_dest_path)

            try:

                # write image to wallpaper path
                download_write = open(image_dest_path, "wb")
                download_write.write(content)
                download_write.close()

            except IOError:

                app_logger_instance.error(u"Failed to save preferred image to %s" % image_dest_path)
                return 1

        if not os.path.exists(image_arch_dir):
            os.makedirs(image_arch_dir)

        # construct full path and filename for archives
        date_now = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
        image_arch_file = u"%s-%s-%s.jpg" % (image_country, date_now, image_hash_web)
        image_arch_path = os.path.join(image_arch_dir, image_arch_file)
        app_logger_instance.info(u"Location to save the archived image file is %s" % image_arch_path)

        try:

            # write image to archive path
            download_write = open(image_arch_path, "wb")
            download_write.write(content)
            download_write.close()

        except IOError:

            app_logger_instance.error(u"Failed to save archived image to %s" % image_arch_path)
            return 1

        app_logger_instance.info(u"Successfully downloaded image")
        return 0

    else:

        app_logger_instance.error(u"Problem downloading image from %s" % image_download_url_web)
        return 1


def monitor(schedule_check_mins):

    # get base url for website
    base_url = config_obj["website"]["base_url"]

    # get image preferred country of origin (this will be whats set as wallpaper)
    image_preferred_country = config_obj["image"]["image_preferred_country"]

    # get image resolution
    image_resolution = config_obj["image"]["image_resolution"]

    # get image destination filename
    image_dest_file = config_obj["image"]["image_dest_file"]
    image_dest_file = os.path.normpath(image_dest_file)

    # get image destination directory
    image_dest_dir = config_obj["image"]["image_dest_dir"]
    image_dest_dir = os.path.normpath(image_dest_dir)

    # get image archive directory
    image_arch_dir = config_obj["image"]["image_arch_dir"]
    image_arch_dir = os.path.normpath(image_arch_dir)

    # get image hash value from config.ini
    image_hash = config_obj["image"]["image_hash"]

    # get list of allowed countries from config.ini
    image_allowed_country = config_obj["image"]["image_allowed_country"]

    # loop over list of allowed countries to download images from
    for image_country in image_allowed_country:

        # construct url for bing json (used to get url for image)
        image_json_url = u"%s/HPImageArchive.aspx?format=js&idx=0&n=1&mkt=%s" % (base_url, image_country)
        app_logger_instance.info(u"Image json download URL is '%s'" % image_json_url)

        # run function to get metadata from bing json
        return_code, image_hash_web, image_download_url_web = image_url(image_json_url=image_json_url, base_url=base_url, image_hash=image_hash, image_resolution=image_resolution)

        if return_code == 0:

            # run function to download image using metadata to construct url
            return_code = image_download(image_download_url_web=image_download_url_web, image_country=image_country, image_preferred_country=image_preferred_country, image_hash_web=image_hash_web, image_dest_dir=image_dest_dir, image_dest_file=image_dest_file, image_arch_dir=image_arch_dir)

            if return_code == 0:

                # append hash value to list in config.ini (used to skip already downloaded images on next run)
                image_hash.append(image_hash_web)
                config_obj["image"]["image_hash"] = image_hash
                config_obj.write()

                app_logger_instance.info(u"All images processed")

        app_logger_instance.info(u"Waiting for next invocation in %s minutes..." % schedule_check_mins)

        # write timestamp to config.ini
        config_obj["general"]["last_check"] = time.strftime("%c")
        config_obj.write()


def scheduler_start():

    schedule_check_mins = config_obj["general"]["schedule_check_mins"]

    app_logger_instance.info(u"Initial check for version changes...")
    monitor(schedule_check_mins)

    # now run monitor_sites function via scheduler
    schedule.every(schedule_check_mins).minutes.do(monitor, schedule_check_mins)

    while True:

        try:

            schedule.run_pending()
            time.sleep(1)

        except KeyboardInterrupt:

            app_logger_instance.warning(u"Keyboard interrupt received, exiting script...")
            sys.exit()


# required to prevent separate process from trying to load parent process
if __name__ == '__main__':

    app_name = "Get-Bing"
    version = "2.0.0"

    app_root_dir = os.path.dirname(os.path.realpath(__file__))

    # set folder path for config files
    config_dir = os.path.join(app_root_dir, u"configs")
    config_dir = os.path.normpath(config_dir)

    # set path for configspec.ini file
    configspec_ini = os.path.join(config_dir, u"configspec.ini")

    # set path for config.ini file
    config_ini = os.path.join(config_dir, u"config.ini")

    # set folder path for log files
    logs_dir = os.path.join(app_root_dir, u"logs")
    logs_dir = os.path.normpath(logs_dir)

    # set path to pdfile
    pidfile = u'/var/run/get-bing.pid'

    # set path for log file
    app_log_file = os.path.join(logs_dir, u"app.log")

    # create configobj instance, set config.ini file, set encoding and set configspec.ini file
    config_obj = configobj.ConfigObj(config_ini, list_values=False, write_empty_values=True, encoding='UTF-8', default_encoding='UTF-8', configspec=configspec_ini, unrepr=True)

    # create config.ini
    create_config()

    user_agent_chrome = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36"

    # custom argparse to redirect user to help if unknown argument specified
    class ArgparseCustom(argparse.ArgumentParser):

        def error(self, message):
            sys.stderr.write('error: %s\n' % message)
            self.print_help()
            sys.exit(2)

    # setup argparse description and usage, also increase spacing for help to 50
    commandline_parser = ArgparseCustom(prog="%s" % app_name, description="%s ver %s" % (app_name, version), usage="%(prog)s [--help] [--config <path>] [--logs <path>] [--pidfile <path>] [--daemon] [--version]", formatter_class=lambda prog: argparse.HelpFormatter(prog, max_help_position=50))

    # add argparse command line flags
    commandline_parser.add_argument(u"--config", metavar=u"<path>", help=u"specify path for config file e.g. --config /opt/get-bing/config/")
    commandline_parser.add_argument(u"--logs", metavar=u"<path>", help=u"specify path for log files e.g. --logs /opt/get-bing/logs/")
    commandline_parser.add_argument(u"--pidfile", metavar=u"<path>", help=u"specify path to pidfile e.g. --pid /var/run/get-bing.pid")
    commandline_parser.add_argument(u"--daemon", action=u"store_true", help=u"run as daemonized process")
    commandline_parser.add_argument(u"--version", action=u"version", version=version)

    # save arguments in dictionary
    args = vars(commandline_parser.parse_args())

    # if dirs specified via command line then set to use this, create if not exists
    if args["config"]:

        config_dir = args["config"]

    if not os.path.exists(config_dir):

        os.makedirs(config_dir)

    if args["logs"]:

        logs_dir = args["logs"]

    if not os.path.exists(logs_dir):

        os.makedirs(logs_dir)

    if args["pidfile"]:

        pidfile = args["pidfile"]

    pid_path = os.path.dirname(pidfile)

    if not os.path.exists(pid_path):

        os.makedirs(pid_path)

    app_log = app_logging()
    app_logger_instance = app_log.get('logger')
    app_handler = app_log.get('handler')

    # check os is not windows and then run main process as daemonized process
    if args["daemon"] is True and os.name != "nt":

        app_logger_instance.info(u"Running as a daemonized process...")

        # specify the logging handler as an exclusion to the daemon, to prevent its output being closed
        daemon_context = daemon.DaemonContext()
        daemon_context.files_preserve = [app_handler.stream]
        daemon_context.open()

    else:

        app_logger_instance.info(u"Running as a foreground process...")

    # run main function
    scheduler_start()
