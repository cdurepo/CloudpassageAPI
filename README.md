# CloudpassageAPI

 **CloudpassageAPI test to user the SDK to gather information and make a report**

## Summary
 Using the python SDK we are going to make a report as outlined in the APIExercise request.  
 We will return info on some of the top issues and accounts.

## Design
 For now it is a single python file to connect and gather all the info and make the report.
 Each step has been made it own function for better code reuse.

## Running API exercise directly
 If you do not or cannot run the docker image you should be able to run the exercise on your own.
You must have python3, pip3, and the cloudpassage API installed to work.
For debian based distros you can use:

```
apt-get install python3 pip3
```

Once that is done you can install the cloudpassage SDK. You can do that using pip

```
pip3 install cloudpassage
```

Once that is done you can run the code in the python directory and give it key and secret arguments.

```
python3 APIExercise.py --key=<API KEY> --secret=<API Secret>
```

## Running API via Docker image
This project can also be run via the Docker image for consistency. Once you have the project cloned you can use the following directions
to build the and run the Docker image.

Build docker image
```
 docker build docker -f docker/Dockerfile.cloudpassage --rm -t cloudpassage/devel
 ```

 Start the image
 ```
 cd docker
 docker-compose up --build
```
Leave that open and open a new command line and go to the same directory you were in

Verify the image is up and running.
```
docker-compose ps
```

Now we can connect to that image and run our API exercise
```
docker exec -it docker_python_1 /usr/bin/python3 APIExercise.py --key=<API Key> --secret=<API Secret>
```
It should then output the report as requested.
