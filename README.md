Install all the required packages mentioned in installments.txt and run jwks2.py to run the server.
The application will automatically create an SQLite database named totally_not_my_privateKeys.db and populate it with RSA keys upon startup. 
This application is running on port 8080 and can be tested using gradebot of CSCE3550 using command ./gradebot project2 to verify output

This application demonstrates basic JWT handling and key management. For production environments, consider additional security measures, such as HTTPS, more complex 
key rotation policies, and thorough validation of incoming data.
