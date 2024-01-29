/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.mycompany.securedataapp;

//imports
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.stream.Collectors;

/*
 * Utils.java
 * 17th November 2021
 * Security Fundamentals and Development CA1 Part 2
 * Group F - Ruby Lennon (x19128355) et al.
 * Description - Class to store GUI utils
 */

public class Utils {
    
    /**
     * Write string to a file and save it to default project location 
     * @param fileName
     * @param encryptedString
     * @throws IOException 
     */
    public static void writeEncryptedStringToFile(String fileName, String encryptedString) throws IOException {
        FileOutputStream outputStream = new FileOutputStream(fileName);
        byte[] strToBytes = encryptedString.getBytes();
        outputStream.write(strToBytes);
        outputStream.close();
    }
      
    /**
     * Reads lines from a text file
     * @param filePath
     * @return 
     */
    public static String readLineByLine(String filePath) {
        String content = null;
        try {
            content = Files.lines(Paths.get(filePath)).collect(Collectors.joining(System.lineSeparator()));
        } catch (IOException e) {
            e.printStackTrace();
        }
        return content;
    }      
    
    
    //method to encrypt string value using Hash (SHA-1 MessageDigest Algorithm)
    public static String HashFormatter(String password){
        MessageDigest sha = null;//Message digests are secure one-way hash functions that take arbitrary-sized data and output a fixed-length hash value
        try{
            sha = MessageDigest.getInstance("SHA-1");//SHA-1 MessagDigest Algorithm selected
        }catch(NoSuchAlgorithmException e){
            System.out.println("No such algorithm");
        }

        byte b[] = password.getBytes();//Get they byte value of password

        byte[] hash = sha.digest(b);//byte array used to store the digested password using SHA-1 algorithm

        String encryptedPassword = new String(hash, StandardCharsets.UTF_8);//converting the hash to a string and storing in encryptedPassword

        return encryptedPassword;//return encryptedPassword

    }
    
    //To run below code create userstore datbase using userstore.sql schema, once created, update code below with localhost username and password
    //method to create a new user in the database
    public static String CreateUser(String username, String password){
        try{
            String returnStatement;//string to restore method return statement
            Connection con = DriverManager.getConnection("jdbc:mysql://localhost:3306/userstore", "root", "RLNCIsqlPass123*");//connect to userstore schema/database on localhost
            String sql = "INSERT INTO users (user_name, password) VALUES (?, ?)";//SQL statement to create new user in users table
            PreparedStatement statement = con.prepareStatement(sql);//prepared statement is more secure than plain statement against SQL injection
            statement.setString(1, username);//set the first statement parameter (?) to the username value
            statement.setString(2, password);//set the second statement parameter (?) to the password value

            statement.executeUpdate();//execute the statement

            con.close();//close connection

            return returnStatement = "New user created";//return this statement
        }catch(SQLException e){
            System.out.println("SQL Error: " + e.getMessage());
            String sqlError;
            sqlError = e.getMessage();
            return sqlError;//return the SQL error
        }
    }
    
    //To run below code create userstore datbase using userstore.sql schema, once created, update code below with localhost username and password
    //method to check if a user exists in the database using username and password
    public static String CheckUser(String username, String password){
        try{
            String returnStatement;//string to restore method return statement
            Connection con = DriverManager.getConnection("jdbc:mysql://localhost:3306/userstore", "root", "RLNCIsqlPass123*");//connect to userstore schema/database on localhost
            String sql = "SELECT * FROM users where user_name = ? and password = ?";//SQL statement
            PreparedStatement statement = con.prepareStatement(sql);//prepared statement is more secure than plain statement against SQL injection
            statement.setString(1, username);//set the first statement parameter (?) to the username value
            statement.setString(2, password);//set the second statement parameter (?) to the password value
            
            ResultSet results = statement.executeQuery();//execute the statement and store results set

            if(results.next()){//if true
                con.close();//close connection
                return returnStatement = "You have successfully logged in.";
            }else{
                con.close();//close connection
                return returnStatement = "Login failed.";
            }

        }catch(SQLException e){
            System.out.println("SQL Error: " + e.getMessage());
            String sqlError;
            sqlError = e.getMessage();
            return sqlError;//return the SQL error
        }
    }
    
    //To run below code create userstore datbase using userstore.sql schema, once created, update code below with localhost username and password
    //method to check if a user exists in the database
    public static String GetUserDetails(String username, String password){
        try{
            String returnStatement;//string to restore method return statement
            Connection con = DriverManager.getConnection("jdbc:mysql://localhost:3306/userstore", "root", "RLNCIsqlPass123*");//connect to userstore schema/database on localhost
            String sql = "SELECT * FROM users WHERE user_name=? AND password=?";//SQL statement
            PreparedStatement statement = con.prepareStatement(sql);//prepared statement is more secure than plain statement against SQL injection
            statement.setString(1, username);//set the first statement parameter (?) to the username value
            statement.setString(2, password);//set the second statement parameter (?) to the password value

            ResultSet results = statement.executeQuery();//execute the statement

            if(results.next()){
                returnStatement = results.getString("PPSN");//get the PPSN column value at first index pointer
                con.close();//close connection
                return returnStatement;//return the PPSN number
            }else{
                con.close();//close connection
                return returnStatement = "Login failed.";
            }

        }catch(SQLException e){
            System.out.println("SQL Error: " + e.getMessage());
            String sqlError;
            sqlError = e.getMessage();
            return sqlError;//prin the SQL error
        }
    }
    
    //To run below code create userstore datbase using userstore.sql schema, once created, update code below with localhost username and password
    //method to update user ppsn number in users table in userstore database
    public static String UpdatePPSN(String username, String password, String ppsn){
        try{
            String returnStatement;//string to restore method return statement
            Connection con = DriverManager.getConnection("jdbc:mysql://localhost:3306/userstore", "root", "RLNCIsqlPass123*");//connect to userstore schema/database on localhost
            String sql = "UPDATE users SET PPSN=? WHERE user_name=? and password=?";//SQL statement to update PPSN for specified user in the users table
            PreparedStatement statement = con.prepareStatement(sql);//prepared statement is more secure than plain statement against SQL injection
            statement.setString(1, ppsn);//set the first statement parameter (?) to the ppsn value
            statement.setString(2, username);//set the second statement parameter (?) to the password value
            statement.setString(3, password);//set the second statement parameter (?) to the password value

            statement.executeUpdate();//execute the statement

            con.close();//close connection

            return returnStatement = "PPSN Encrypted and stored in userstore database";//reutrn the following
        }catch(SQLException e){
            System.out.println("SQL Error: " + e.getMessage());
            String sqlError;
            sqlError = e.getMessage();
            return sqlError;//print the SQL error
        }
    }
    
}
