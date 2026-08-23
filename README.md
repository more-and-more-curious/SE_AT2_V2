# Tutti

A task assignment and study tracker app for students and teachers.

## Description

A full-stack webapp with multi-role signup and login functionality. A mix of Google Classroom and Flora where teachers are able to create a class where they can add students, set tasks, and monitor their progress. Students are able to complete tasks and log study sessions. 

## Getting Started

### Executing program

* Open VSCode (or other software) and create a virtual environment in the terminal
* Using the requirements.txt install required libraries
```
pip install -r requirements.txt
```
* In the terminal, create a API key
```
export API_KEY="AnyRandomString12345"
```
* Run the code (will vary based on software)
```
python3 app.py
```

## Help

Due to limiter and timeout, logged in sessions expire after 15 minutes and the limit for all routes is 20 connections per minute and 5 specifically for the login route. You will be redirected to an error page if this occurs and will have to wait out the limiter. 

## Authors

more-and-more-curious
