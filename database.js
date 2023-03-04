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

export async function getpost(){
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
      const message = token
  
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

export async function doctorSignup(FirstName, SurName, Email, PhoneNumber, Password, DateCreated, IsActive) {
  // const { FirstName, SurName, Email, PhoneNumber, Password, DateCreated, IsActive } = doctorData
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
        let timeZone = 'Australia/Sydney';
        let datetime = moment(DateCreat).tz(timeZone).format('YYYY-MM-DD HH:mm:ss');
        // const datetime = DateCreat.toISOString().substr(0, 19).replace('T', ' ');
        const token = Math.floor(100000 + Math.random() * 900000).toString();
        const [res] = await connection.query(`
        INSERT INTO doctor (FirstName, SurName, Email, PhoneNumber, Password, DateCreated, IsActive)
        VALUES (?, ?, ?, ?, ?, ?, ?)`, [FirstName, SurName, Email, PhoneNumber, Password, datetime, 1])
        const user = res.insertId
      //  return getpos(user)
 
        const [res2] = await connection.query(`INSERT INTO users (Email, Password, FirstName, SurName, Token, EmailConfirmed, Role, IsActive) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, [Email, Password, FirstName, SurName, token, 0, "Doctor", 1])
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

export async function getOTP(Email) {
  try {
    const [rows] = await pool.query('SELECT Token FROM users WHERE Email = ?', Email);
    if (rows.length === 0) {
      throw new Error('No OTP found for the given email');
    }
    return rows[0].Token;
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


export async function login(Email, Password) {
  try {
  const [rows] = await pool.query(`SELECT * FROM users WHERE Email = ?`, [Email]);
  if (!rows[0]) {
  return { error: 'Email is not registered' };
  }

  if (rows[0].EmailConfirmed === 0) {
    return { redirect: '/verify-otp' };
  }
  const [dows] = await pool.query(`SELECT * FROM doctor WHERE Email = ?`, [Email]);
  const match = await bcrypt.compare(Password, rows[0].Password);
  if (match) {
  const usersId = rows[0].id;
  const docId = dows[0].DoctorId
   await pool.query(`UPDATE users SET IsActive = 1 WHERE id = ?`, [usersId]);
   await pool.query(`UPDATE doctor SET IsActive = 1 WHERE DoctorId = ?`, [docId]);
  const { FirstName, Email, id, Role } = rows[0];
  const {DoctorId} = dows[0]
  // create and return JWT
  return { token: jwt.sign({ FirstName, Email, id, Role, DoctorId }, secret) };
  } else {
  return { error: 'Incorrect password' };
  }
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
      // Send an email to the doctor notifying them that their account has been accepted
      const doctor = await getDoctorById(DoctorId);
      const Email = doctor.Email;
      const text = 'Your account has been accepted by the admin. You can now log in to your account.';
      // await sendEmail(Email, text);
      
      return { success: true, message: 'Doctor accepted successfully' };
    } else if (IsApproved === 0) {
      // Send an email to the doctor notifying them that their account has been declined
      const [res] = await pool.query('UPDATE doctor_document SET RejectDeadline = ? WHERE DoctorId = ?', [date, DoctorId]);
      const doctor = await getDoctorById(DoctorId);
      const Email = doctor.Email;
      const text = 'Your account has been declined by the admin. Please contact support for more information.';
      // await sendEmail(Email, text);
      
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



export async function docSched(DoctorId, ScheDate, ScheTime, DateCreated) {

  let DateCreat = new Date()
        let timeZone = 'Australia/Sydney';
        let datetime = moment(DateCreat).tz(timeZone).format('YYYY-MM-DD HH:mm:ss');

  try {
    await pool.query(`INSERT INTO doctorschedule (DoctorId, ScheDate, ScheTime, DateCreated) VALUES (?, ?, ?, ?)`,
     [DoctorId, ScheDate, ScheTime, datetime,])
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

  try {
      const emailRegex = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;
      if (!emailRegex.test(Email)) {
          return {error: 'Invalid Email'}
      }
      
      const [existingUser] = await pool.query(`SELECT * FROM patient WHERE Email = ?`, [Email]);
      if (existingUser[0]) {
          return { error: 'Email already exists' };
      }

      let DateCreat = new Date()
      let timeZone = 'Australia/Sydney';
      let datetime = moment(DateCreat).tz(timeZone).format('YYYY-MM-DD HH:mm:ss');
      // const datetime = DateCreat.toISOString().substr(0, 19).replace('T', ' ');

      const [res] = await pool.query(`
      INSERT INTO patient (FirstName, SurName, Email, PhoneNumber, Password, DateCreated, IsActive, Iscompleted)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `, [FirstName, SurName, Email, PhoneNumber, Password, datetime, 1, 0])
      const user = res.insertId
     return getpo(user)
     
  } catch (error) {
        console.log(error);
        return { error: 'An error occurred' };
  }

}

export async function patientLogin(Email, Password) {
  try {
  const [rows] = await pool.query(`SELECT * FROM patient WHERE Email = ?`, [Email]);
  if (!rows[0]) {
  return { error: 'Email is not registered' };
  }
  const match = await bcrypt.compare(Password, rows[0].Password);
  if (match) {
  const patientId = rows[0].PatientId;
  await pool.query(`UPDATE patient SET IsActive = 1 WHERE PatientId = ?`, [patientId]);
  const { FirstName, Email, PatientId } = rows[0];
  // create and return JWT
  return { token: jwt.sign({ FirstName, Email, PatientId }, secret) };
  } else {
  return { error: 'Incorrect password' };
  }
} catch (err) {
  console.log(err);
  return { error: 'An error occurred' };
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




































// sgMail.setApiKey(process.env.SENDGRID_API_KEY);
// const msg = {
//   to: email, 
//   from: 'Grapple',
//   subject: 'Subject of your email',
//   text: `Please click the following link to verify your email: http://localhost:3000/verify?token=${token}`,
//   html: `<p>Please click the following link to verify your email:</p><p><a href="http://localhost:3000/verify?token=${token}">Verify Email</a></p>`,
// };

// sgMail.send(msg)
//   .then(() => {
//     console.log('Email sent');
//   })
//   .catch((error) => {
//     console.error(error);
//   });

// Define a function to log in an existing user
// const login = async (email, password) => {
//   // Look up the user by email address
//   const [result] = await pool.query('SELECT * FROM users WHERE email = ?', [email]);
//   if (result.length === 0) {
//     return { error: 'User not found' };
//   }

//   // Check if the user's email has been verified
//   if (!result[0].verified) {
//     return { error: 'Email not verified' };
//   }

//   // Check if the password is correct
//   const passwordMatch = await bcrypt.compare(password, result[0].password);
//   if (!passwordMatch) {
//     return { error: 'Invalid password' };
//   }

//   // Generate a JWT token
//   const token = jwt.sign({ id: result[0].id, email: result[0].email }, process.env.JWT_SECRET);

//   // Return the JWT token
//   return { token };
// };

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

// Define a route for user signups
// app.post('/signup', async (req, res) => {
//   try {
//     const { email, password } = req.body;

//     // Call the signup function to create a new user
//     const result = await signup(email, password);

//     // If there was an error, return a 400 response with the error message
//     if (result.error) {
//       return res.status(400).json({ error: result.error });
//     }

//     // Otherwise, return a 201 response with the new user's ID
//     res.status(201).json({ id: result.id });



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

