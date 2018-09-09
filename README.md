# README #

This README would normally document whatever steps are necessary to get your application up and running.

### Auth Server ###

* Responsible for Authentication and Authorisation
* Spring security + JWT + Discovery client for Eureka server + flyway + Mysql

###Responsibilities###

* User credentials validation
* Token generation (Access Token and Refresh Token)
* Token Validation
* New access Token generation from refresh token
* Access User details (user name , roles etc) from valid JWT token
* Authorisation based on user roles
* Register itself on Eureka server as a client

### user details ###

* using Mysql for storing user details
* flyway for versioning control of database

### running on ###
9001
Discovery server should be up before running auth server