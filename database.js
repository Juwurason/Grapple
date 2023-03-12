import mysql from "mysql2"
import dotenv from 'dotenv'
import bcrypt from "bcrypt"
import jwt from "jsonwebtoken"
import nodemailer from "nodemailer"
import { v4 as uuidv4 } from 'uuid';
import axios from 'axios'
import moment from "moment-timezone"
// Dependencies
import multer from "multer"
import admin from "firebase-admin"
import sgMail from "@sendgrid/mail"
import { async } from "@firebase/util"
dotenv.config()
const secret = 'secretkey';

const pool = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    database: process.env.DB_NAME,
    password: process.env.DB_PASSWORD,
    waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
}).promise()

export async function getAllDoctor(){
    const [rows] = await pool.query("SELECT * FROM doctor")
    return rows
}

export async function getDoctorById(id){
        const [rows] = await pool.query(`SELECT * FROM doctor WHERE DoctorId = ?`, [id])
        return rows[0]
    }

export async function getpo(id){
        const [rows] = await pool.query(`SELECT * FROM patient WHERE PatientId = ?`, [id])
        return rows[0]
    }
    
export async function getAllDoctorDocument(){
        const [rows] = await pool.query(`SELECT * FROM doctor_document`)
        return rows[0]
    }

export async function getAllDoctorDocumentById(DoctorId) {
  const [rows] = await pool.query(`SELECT * FROM doctor_document WHERE DoctorId = ?`, [DoctorId])
  return rows
}

export async function getpharmacy(id){
        const [rows] = await pool.query(`SELECT * FROM pharmacy WHERE PharmacyId = ?`, [id])
        return rows[0]
    }

export async function getpharmacyAd(id){
        const [rows] = await pool.query(`SELECT * FROM pharmaceutical_admin WHERE PharmacyId = ?`, [id])
        return rows[0]
    }

    // Authenticate admin user
    export async function authenticateAdmin(username, password) {
      try {
      const [rows] = await pool.query(`SELECT * FROM admin WHERE username = ?`, [username]);
    
      const match = await bcrypt.compare(password, rows[0].password);
      if (match) {
      const { username } = rows[0];
      // create and return JWT
      return { token: jwt.sign({ username }, secret) };
      } else {
      return { error: 'Incorrect password' };
      }
    } catch (err) {
      console.log(err);
      return { error: 'An error occurred' };
    }
    }
    

export async function sendVerificationEmail(Email, token) {
    try {
      const recipient = Email;
      const mailFrom = 'Grapple';
      const subject = 'Verify';
      const message = `Here Is Your One Time Password(OTP) to Validate your Email Address ${token}`
  
      const response = await axios.post('http://profitmax-001-site8.ctempurl.com/api/Account/general_email_sending', {
        recipient: recipient,
        mailFrom: mailFrom,
        subject: subject,
        message: message
      });
  
      if (response.status === 200) {
        console.log('Message sent successfully');
      } else {
        console.error('Failed to send message');
      }
    } catch (error) {
      console.error('Error sending message:', error);
    }
  }

export async function doctorSignup(FirstName, SurName, Email, PhoneNumber, Password, DateCreated, IsActive, Status) {
   const connection = await pool.getConnection();
   await connection.beginTransaction();

    try {
        const emailRegex = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;
        if (!emailRegex.test(Email)) {
          return {error: 'Invalid Email'}
        }

        const [existingUser] = await connection.query(`SELECT * FROM doctor WHERE Email = ?`, [Email]);
        if (existingUser[0]) {
            return { error: 'Email already exists' };
        }
       
        let DateCreat = new Date()
        let timeZone = 'Africa/Lagos';
        let datetime = moment(DateCreat).tz(timeZone).format('YYYY-MM-DD HH:mm:ss');
        const expiry = new Date(DateCreat.getTime() + 10 * 60 * 1000);
        const token = Math.floor(100000 + Math.random() * 900000).toString();
        const [res] = await connection.query(`
        INSERT INTO doctor (FirstName, SurName, Email, PhoneNumber, Password, DateCreated, IsActive, Status)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, [FirstName, SurName, Email, PhoneNumber, Password, datetime, 1, 0])
        const user = res.insertId
      //  return getpos(user)
 
        const [res2] = await connection.query(`INSERT INTO users (Email, Password, FirstName, SurName, Token, EmailConfirmed, Role, IsActive, TokenExpired) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`, [Email, Password, FirstName, SurName, token, 0, "Doctor", 1, expiry])
        const aspnetuserId = res2.insertId
      //  return getpos(user)
      await sendVerificationEmail(Email, token);
      
      await connection.commit();

      return {user, aspnetuserId}
       
    } catch (error) {
      await connection.rollback();
      console.log(error);
          return { error: 'An error occurred' };
    } finally {
      connection.release();
    }

 }

 export async function resendOTP(Email) {
  // Delete any existing OTPs for this email
  await pool.query('UPDATE users SET Token = NULL WHERE Email = ?', Email);

  const token = Math.floor(100000 + Math.random() * 900000).toString();

  let now = new Date();
  const newExpired = new Date(now.getTime() + 10 * 60 * 1000);

  await pool.query('UPDATE users SET Token = ?, TokenExpired = ? WHERE Email = ?', [token, newExpired, Email]);
  // Generate and save a new OTP
   await sendVerificationEmail(Email, token);

  return { message: 'A new OTP has been sent to your registered email address.' };
}

export async function getOTP(Email) {
  try {
    const [rows] = await pool.query('SELECT Token, TokenExpired FROM users WHERE Email = ?', Email);
    if (rows.length === 0) {
      throw new Error('No OTP found for the given email');
    }
    const { Token, TokenExpired } = rows[0];
      let token = Token
    let now = new Date();
    const expiry = new Date(TokenExpired);
    console.log(now, expiry);
    if (now > expiry) {
      await resendOTP(Email)
      return { error: 'OTP has expired. A new OTP has been sent to your registered email address.' };
    } else{
      await sendVerificationEmail(Email, token)
      return token;
    }
    
  } catch (error) {
    console.error('Error while getting OTP:', error);
    throw error;
  }
}



export async function deleteOTP(Email) {
  try {
    // Update the database to confirm the email
    const [updateConfirmationResult] = await pool.query('UPDATE users SET EmailConfirmed = 1 WHERE Email = ?', Email);

    // Update the database to delete the OTP token
    const [updateTokenResult] = await pool.query('UPDATE users SET Token = NULL WHERE Email = ?', Email);

    // Return success message
    return { message: `OTP has been deleted` };
  } catch (error) {
    console.error('Error deleting OTP:', error);
    throw new Error('Error deleting OTP');
  }
}


export async function login(email, Password) {
  try {
  const [rows] = await pool.query(`SELECT * FROM users WHERE Email = ?`, [email]);
  if (!rows[0]) {
  return { error: 'Email is not registered' };
  }

  if (rows[0].EmailConfirmed === 0) {
    return ({ message: 'Email not verified', email:Email });
  }
  
  const match = await bcrypt.compare(Password, rows[0].Password);
  if (!match) {
    return { error: 'Incorrect password' };
  }

   const userId = rows[0].id;
    const role = rows[0].Role;
    await pool.query('UPDATE users SET IsActive = 1 WHERE id = ?', [userId]);
    const { FirstName, SurName, Email, id } = rows[0];
    let doctorId, status;
    if (role === 'Doctor') {
      const [doctor] = await pool.query('SELECT * FROM doctor WHERE Email = ?', [email]);
      if (doctor) {
        doctorId = doctor[0].DoctorId;
        status = doctor[0].Status;
      }
    }
    let patientId;
    if (role === 'Patient') {
      const [patient] = await pool.query('SELECT * FROM patient WHERE Email = ?', [email]);
      if (patient) {
        patientId = patient[0].PatientId;
      }
    }
    // create and return JWT
    return { token: jwt.sign({ FirstName, SurName, Email, id, Role: role, DoctorId: doctorId, Status: status, PatientId: patientId }, secret) };
 
  // if (match) {
  // const usersId = rows[0].id;
  // const docId = dows[0].DoctorId
  //  await pool.query(`UPDATE users SET IsActive = 1 WHERE id = ?`, [usersId]);
  //  await pool.query(`UPDATE doctor SET IsActive = 1 WHERE DoctorId = ?`, [docId]);
  // const { FirstName, SurName, Email, id, Role } = rows[0];
  // const {DoctorId, Status} = dows[0]
  // // create and return JWT
  // return { token: jwt.sign({ FirstName, SurName, Email, id, Role, DoctorId, Status }, secret) };
  // } else {
  // return { error: 'Incorrect password' };
  // }
} catch (error) {
  console.log(error);
  return { error: 'An error occurred' };
}
}


export async function logout(DoctorId) {
  try {
    // update IsActive to 0 for the doctor
    const [rows] =  await pool.query(`UPDATE doctor SET IsActive = 0 WHERE DoctorId = ?`, [DoctorId]);
    return { message: 'User logged out successfully', rows };
  } catch (error) {
    console.log(error);
    return { error: 'An error occurred while logging out' };
  }
}

  

export const checkRejectedDocument = async (DoctorId) => {
  try {
    const [result] = await pool.query('SELECT * FROM doctor_document WHERE DoctorId = ? AND Verify = 0', [DoctorId]);

    if (result.length > 0) {
      const lastRejectedDate = new Date(result[0].RejectDeadline);
      const currentDate = new Date();

      // Check if 10 days have passed since the last rejection
      if (currentDate.getTime() - lastRejectedDate.getTime() >= 10 * 24 * 60 * 60 * 1000) {
        return { success: true, message: 'Document uploaded successfully' };
      } else {
        return { success: false, message: 'You cannot upload another document yet. Please wait for 10 days from the date of the last rejection.' };
      }
    } else {
      const [doctor] = await pool.query('SELECT * FROM doctor WHERE DoctorId = ?', [DoctorId]);

      if (doctor.length > 0) {
        await pool.query(`UPDATE doctor SET Status = 1 WHERE DoctorId = ?`, [DoctorId]);
        return { success: true, message: 'Document uploaded successfully' };
      } else {
        throw new Error('Doctor does not exist');
      }
    }
  } catch (error) {
    console.log(error);
    throw new Error('An error occurred while checking for rejected documents');
  }
};


// Upload a new document
export const uploadNewDocument = async (DoctorId, DocumentUrl, DocumentName, DateCreated) => {
  try {

    let DateCreat = new Date()
    let timeZone = 'Australia/Sydney';
    let datetime = moment(DateCreat).tz(timeZone).format('YYYY-MM-DD HH:mm:ss');
    const [uploadResult] = await pool.query('INSERT INTO doctor_document (DoctorId, DocumentUrl, DocumentName, DateCreated) VALUES (?, ?, ?, ?)', [DoctorId, DocumentUrl, DocumentName, datetime]);
    await pool.query(`UPDATE doctor SET Status = 1 WHERE DoctorId = ?`, [DoctorId]);
    return { success: true, message: 'Document uploaded successfully' };
  } catch (error) {
    console.log(error);
    throw new Error('An error occurred while uploading the document');
  }
};

export async function sendEmail(Email, text) {
  try {
    const recipient = Email;
    const mailFrom = 'Grapple';
    const subject = 'Account Status';
    const message = text

    const response = await axios.post('http://profitmax-001-site8.ctempurl.com/api/Account/general_email_sending', {
      recipient: recipient,
      mailFrom: mailFrom,
      subject: subject,
      message: message
    });

    if (response.status === 200) {
      console.log('Message sent successfully');
    } else {
      console.error('Failed to send message');
    }
  } catch (error) {
    console.error('Error sending message:', error);
  }
}

export const acceptOrDeclineDoctor = async (DoctorId, IsApproved) => {
  try {
    // Update the doctor's status in the database
    const [result] = await pool.query('UPDATE doctor SET IsApproved = ? WHERE DoctorId = ?', [IsApproved, DoctorId]);
    
    if (result.affectedRows === 0) {
      throw new Error('Doctor not found');
    }

    let DateCreat = new Date();
    let date = moment(DateCreat).format('YYYY-MM-DD');

    if (IsApproved === 1) {
      const [res] = await pool.query('UPDATE doctor_document SET Verify = 1 WHERE DoctorId = ?', [DoctorId]);
      await pool.query(`UPDATE doctor SET Status = 2 WHERE DoctorId = ?`, [DoctorId]);
      // Send an email to the doctor notifying them that their account has been accepted
      const doctor = await getDoctorById(DoctorId);
      const Email = doctor.Email;
      const text = 'Your account has been accepted by the admin. You can now log in to your account.';
      await sendEmail(Email, text);
      
      return { success: true, message: 'Doctor accepted successfully' };
    } else if (IsApproved === 0) {
      // Send an email to the doctor notifying them that their account has been declined
      const [res] = await pool.query('UPDATE doctor_document SET RejectDeadline = ? WHERE DoctorId = ?', [date, DoctorId]);
      await pool.query(`UPDATE doctor SET Status = 3 WHERE DoctorId = ?`, [DoctorId]);
      const doctor = await getDoctorById(DoctorId);
      const Email = doctor.Email;
      const text = 'Your account has been declined by the admin. Please contact support for more information.';
      await sendEmail(Email, text);
      
      return { success: true, message: 'Doctor declined successfully' };
    } else {
      throw new Error('Invalid status');
    }
  } catch (error) {
    console.log(error);
    throw new Error('An error occurred while accepting or declining the doctor');
  }
};

export async function editDoc(
  id, Gender, FirstName, SurName, MiddleName, AboutMe, Address,
  Postcode, PhoneNumber, Qualification, ImageUrl, Country,
  State, City, DateOfBirth) {
  try { await pool.query(`UPDATE doctor SET Gender = ?, FirstName = ?, SurName = ?, 
  MiddleName = ?, AboutMe = ?, Address = ?, Postcode = ?, PhoneNumber = ?, 
  Qualification = ?, ImageUrl = ?, Country = ?, State = ?, City = ?, DateOfBirth = ? WHERE DoctorId = ?`, [
    Gender, FirstName, SurName, MiddleName, AboutMe, Address,Postcode, PhoneNumber,
     Qualification, ImageUrl, Country, State, City, DateOfBirth, id])
  return { message: 'Doctor details updated successfully' };
  } catch (err) {
    console.error(err);
     return { error: 'An error occurred while updating the doctor details' };
  }
}

export async function docServiceFee(DoctorId, Service, Description, Rate, ServiceCharge, DateCreated) {

  let DateCreat = new Date()
        let timeZone = 'Australia/Sydney';
        let datetime = moment(DateCreat).tz(timeZone).format('YYYY-MM-DD HH:mm:ss');

  try {
    await pool.query(`INSERT INTO doctorservicefee (DoctorId, Service, Description, Rate, ServiceCharge, DateCreated) VALUES (?, ?, ?, ?, ?, ?)`,
     [DoctorId, Service, Description, Rate, ServiceCharge, datetime])
  } catch (error) {
    console.log(error);
    return { error: 'An error occurred while inserting the doctor schedule' }
  }
}

export async function docSched(DoctorId, Days, FromTimeOfDay, ToTimeOfDay, Activities, DateCreated) {

  let DateCreat = new Date()
        let timeZone = 'Australia/Sydney';
        let datetime = moment(DateCreat).tz(timeZone).format('YYYY-MM-DD HH:mm:ss');

  try {
    await pool.query(`INSERT INTO doctorschedule (DoctorId, Days, FromTimeOfDay, ToTimeOfDay, Activities, DateCreated,) VALUES (?, ?, ?, ?, ?, ?)`,
     [DoctorId, Days, FromTimeOfDay, ToTimeOfDay, Activities, datetime])
  } catch (error) {
    console.log(error);
    return { error: 'An error occurred while inserting the doctor schedule' }
  }
}

export async function getDoctorAppointments(DoctorId) {
  try {
    const [rows] = await pool.query(`SELECT * FROM doctorschedule WHERE DoctorId = ?`, [DoctorId]);
    return rows;
  } catch (error) {
    console.log(error);
    return { error: 'An error occurred while getting doctor appointments' };
  }
}

// Function to delete expired appointments
export async function deleteExpiredAppointments() {
  try {
    const appointments = await pool.query(`SELECT * FROM doctorschedule`);
    appointments.forEach(async appointment => {
      if (moment(appointment.ScheDate).isBefore(moment().subtract(1, 'days'))) {
        await pool.query(`DELETE FROM doctorschedule WHERE id = ?`, [doctorschedule.id]);
      }
    });
  } catch (error) {
    console.log(error);
  }
}

// Schedule to run the function every day at midnight
setInterval(deleteExpiredAppointments, 24 * 60 * 60 * 1000);


export async function patientSignup(FirstName, SurName, Email, PhoneNumber, Password, DateCreated, IsActive, Iscompleted) {
  // const { FirstName, SurName, Email, PhoneNumber, Password, DateCreated, IsActive } = doctorData
   const connection = await pool.getConnection();
   await connection.beginTransaction();

    try {
        const emailRegex = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;
        if (!emailRegex.test(Email)) {
          return {error: 'Invalid Email'}
        }
        
        const [existingUser] = await connection.query(`SELECT * FROM users WHERE Email = ?`, [Email]);
        if (existingUser[0]) {
            return { error: 'Email already exists' };
        }

        let DateCreat = new Date()
        let timeZone = 'Australia/Sydney';
        let datetime = moment(DateCreat).tz(timeZone).format('YYYY-MM-DD HH:mm:ss');
        // const datetime = DateCreat.toISOString().substr(0, 19).replace('T', ' ');
        const token = Math.floor(100000 + Math.random() * 900000).toString();
        const [res] = await connection.query(`
        INSERT INTO patient (FirstName, SurName, Email, PhoneNumber, Password, DateCreated, IsActive, Iscompleted)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, [FirstName, SurName, Email, PhoneNumber, Password, datetime, 1, 0])
        const user = res.insertId
      //  return getpos(user)
 
        const [res2] = await connection.query(`INSERT INTO users (Email, Password, FirstName, SurName, Token, EmailConfirmed, Role, IsActive) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, [Email, Password, FirstName, SurName, token, 0, "Patient", 1])
        const aspnetuserId = res2.insertId
      //  return getpos(user)
      await sendVerificationEmail(Email, token);
      
      await connection.commit();

      return {user, aspnetuserId}
       
    } catch (error) {
      await connection.rollback();
      console.log(error);
          return { error: 'An error occurred' };
    } finally {
      connection.release();
    }

 }

 export async function editPatient(
  id, FirstName, SurName, MiddleName, Address, PhoneNumber, Gender, ImageUrl, Country,
  State, City, DateOfBirth, HomePhone, NextOfKin, Relationship,
  KinPostcode, KinAddress, KinCountry, KinCity, KinEmail, Suburb, KinState, KinPhoneNumber,
  BloodGroup, BloodPressure, Genotype) {
  try { await pool.query(`UPDATE patient SET FirstName = ?, SurName = ?, 
  MiddleName = ?, Address = ?, PhoneNumber = ?, Gender = ?,
   ImageUrl = ?, Country = ?, State = ?, City = ?, DateOfBirth = ?,
    HomePhone = ?, NextOfKin = ?, Relationship = ?,
   KinPostcode = ?, KinAddress = ?, KinCountry = ?, KinCity = ?, KinEmail = ?, Suburb = ?, 
   KinState = ?, KinPhoneNumber = ?, BloodGroup = ?, BloodPressure = ?, Genotype = ? WHERE PatientId = ?`, [
   FirstName, SurName, MiddleName, Address, PhoneNumber,
   Gender, ImageUrl, Country, State, City, DateOfBirth, HomePhone, NextOfKin, Relationship,
   KinPostcode, KinAddress, KinCountry, KinCity, KinEmail, Suburb, KinState, KinPhoneNumber,
    BloodGroup, BloodPressure, Genotype, id])
  return { message: 'Doctor details updated successfully' };
  } catch (err) {
    console.error(err);
     return { error: 'An error occurred while updating the doctor details' };
  }
}


export async function patientHealth (PatientId, DateCreated) {
  
  let DateCreat = new Date()
  let timeZone = 'Australia/Sydney';
  let datetime = moment(DateCreat).tz(timeZone).format('YYYY-MM-DD HH:mm:ss');

try {
await pool.query(`INSERT INTO patient_health_care (PatientId, DateCreated) VALUES (?, ?)`,
[PatientId, datetime])
} catch (error) {
console.log(error);
return { error: 'An error occurred while inserting the doctor schedule' }
}
}


export async function pharmacySignup(PharmacyName, PharmacyAddress, PharmacyEmail, PharmacyPhone, DateCreated) {

  try {
      const emailRegex = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;
      if (!emailRegex.test(PharmacyEmail)) {
          return {error: 'Invalid Email'}
      }
      
      const [existingUser] = await pool.query(`SELECT * FROM pharmacy WHERE PharmacyEmail = ?`, [PharmacyEmail]);
      if (existingUser[0]) {
          return { error: 'Email already exists' };
      }

      let DateCreat = new Date()
      let timeZone = 'Australia/Sydney';
      let datetime = moment(DateCreat).tz(timeZone).format('YYYY-MM-DD HH:mm:ss');
      // const datetime = DateCreat.toISOString().substr(0, 19).replace('T', ' ');

      const [res] = await pool.query(`
      INSERT INTO pharmacy (PharmacyName, PharmacyAddress, PharmacyEmail, PharmacyPhone, DateCreated)
      VALUES (?, ?, ?, ?, ?)
      `, [PharmacyName, PharmacyAddress, PharmacyEmail, PharmacyPhone, datetime])
      const user = res.insertId
     return getpharmacy(user)
     
  } catch (error) {
        console.log(error);
        return { error: 'An error occurred' };
  }

}

export async function pharmacyAdmin(FirstName, SurName, Email, PhoneNumber, PharmacyId, Password, Iscompleted, IsActive, DateCreated) {

  const emailRegex = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;
  if (!emailRegex.test(Email)) {
      return {error: 'Invalid Email'}
  }
  
  const [existingUser] = await pool.query(`SELECT * FROM pharmaceutical_admin WHERE Email = ?`, [Email]);
  if (existingUser[0]) {
      return { error: 'Email already exists' };
  }

  let DateCreat = new Date()
        let timeZone = 'Australia/Sydney';
        let datetime = moment(DateCreat).tz(timeZone).format('YYYY-MM-DD HH:mm:ss');

  try {
    const [res] = await pool.query(`INSERT INTO pharmaceutical_admin (FirstName, SurName, Email, PhoneNumber, PharmacyId,  Password, Iscompleted, IsActive, DateCreated) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`, [FirstName, SurName, Email, PhoneNumber, PharmacyId, Password, 0, 1, datetime])
    const user = res.insertId
    return getpharmacyAd(user)
  } catch (error) {
    console.log(error);
    return { error: 'An error occurred while inserting the pharmacy' }
  }
}


export async function pharmacyAdminLogin(Email, Password) {
  try {
  const [rows] = await pool.query(`SELECT * FROM pharmaceutical_admin WHERE Email = ?`, [Email]);
  if (!rows[0]) {
  return { error: 'Email is not registered' };
  }
  const match = await bcrypt.compare(Password, rows[0].Password);
  if (match) {
  const PharmaceuticalAdminId = rows[0].Pharmaceutical_AdminId;
  await pool.query(`UPDATE pharmaceutical_admin SET IsActive = 0 WHERE Pharmaceutical_AdminId = ?`, [PharmaceuticalAdminId]);
  const { FirstName, Email, Pharmaceutical_AdminId } = rows[0];
  // create and return JWT
  return { token: jwt.sign({ FirstName, Email, Pharmaceutical_AdminId }, secret) };
  } else {
  return { error: 'Incorrect password' };
  }
} catch (err) {
  console.log(err);
  return { error: 'An error occurred' };
}
}


export async function saveImageUrlToDatabase(url) {
  try {
    await pool.query(`INSERT INTO images (url) VALUES (?)`, [url]);
    // console.log(url);
    return { success: true };
  } catch (error) {
   console.log(error);
    return { error: 'An error occurred' };
  }
}

export async function saveMessageToDatabase(message) {
  try {
    const query = 'INSERT INTO messages (message) VALUES (?)';
    await pool.query(query, [message]);
    console.log('Message saved to database');
  } catch (error) {
    console.error(`Error saving message to MySQL: ${error}`);
  }
}

































// Define a middleware function to check if a user is authenticated
const authMiddleware = async (req, res, next) => {
  try {
    // Get the JWT token from the Authorization header
    const token = req.header('Authorization').replace('Bearer ', '');

    // Verify the token and extract the user ID
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const userId = decoded.id;

    // Look up the user by ID
    const [result] = await pool.query('SELECT * FROM users WHERE id = ?', [userId]);
    if (result.length === 0) {
      throw new Error('User not found');
    }

    // Check if the user's email has been verified
    if (!result[0].verified) {
      throw new Error('Email not verified');
    }

    // Attach the user object to the request object and proceed to the next middleware
    req.user = result[0];
    next();
  } catch (error) {
    res.status(401).json({ error: 'Not authorized' });
  }
};

async function performTransaction() {
    const connection = await pool.getConnection();
    connection.beginTransaction(async (err) => {
      if (err) {
        throw err;
      }
      try {
        await doctorSignup()
        await login();
        connection.commit((err) => {
          if (err) {
            return connection.rollback(() => {
              throw err;
            });
          }
          console.log('Transaction completed');
        });
      } catch (err) {
        connection.rollback(() => {
          throw err;
        });
      }
    });
    connection.release();
  }
  
  performTransaction();









































  // export async function updateAppointStatus(AppointId, status) {
//   try {
//     await pool.query(`
//     UPDATE doc_sched_status SET Status = ? WHERE AppointId = ?`, [status, AppointId])
//   } catch (error) {
//     console.log(error);
//     return { error: 'An error occurred while updating the appointment status' }
//   }
// }


// export async function createpost(title, body) {
//    const [res] = await pool.query(`
//     INSERT INTO postss (title, body)
//     VALUES (?, ?)
//     `, [title, body])
//     const id = res.insertId
//     return getposts(id)
// }

