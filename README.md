# CloudpassageAPI

 ** CloudpassageAPI test to user the SDK to gather information and make a report **

 ## Summary
 Using the python SDK we are going to make a report as outlined in the APIExercise request.  
 We will return info on some of the top issues and accounts.

 ## Design
 For now it is a single python file to connect and gather all the info and make the report.
 Each step has been made it own function for better code reuse.

 ## Running API exersise.  
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
