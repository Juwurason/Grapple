import mysql from "mysql2"
import dotenv from 'dotenv'
import bcrypt from "bcrypt"
import jwt from "jsonwebtoken"
import moment from "moment-timezone"
dotenv.config()
const secret = 'secretkey';


const pool = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    database: process.env.DB_NAME,
    password: process.env.DB_PASSWORD,
}).promise()

export async function getpost(){
    const [rows] = await pool.query("SELECT * FROM doctor")
    return rows
}

export async function getpos(id){
        const [rows] = await pool.query(`SELECT * FROM doctor WHERE DoctorId = ?`, [id])
        return rows[0]
    }

export async function getpo(id){
        const [rows] = await pool.query(`SELECT * FROM patient WHERE PatientId = ?`, [id])
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

export async function doctorSignup(FirstName, SurName, Email, PhoneNumber, Password, DateCreated, IsActive) {

    try {
        const emailRegex = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;
        if (!emailRegex.test(Email)) {
          return {error: 'Invalid Email'}
        }
        
        const [existingUser] = await pool.query(`SELECT * FROM doctor WHERE Email = ?`, [Email]);
        if (existingUser[0]) {
            return { error: 'Email already exists' };
        }

        let DateCreat = new Date()
        let timeZone = 'Australia/Sydney';
        let datetime = moment(DateCreat).tz(timeZone).format('YYYY-MM-DD HH:mm:ss');
        // const datetime = DateCreat.toISOString().substr(0, 19).replace('T', ' ');

        const [res] = await pool.query(`
        INSERT INTO doctor (FirstName, SurName, Email, PhoneNumber, Password, DateCreated, IsActive)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        `, [FirstName, SurName, Email, PhoneNumber, Password, datetime, 1])
        const user = res.insertId
       return getpos(user)
       
    } catch (error) {
          return { error: 'An error occurred' };
    }

 }


export async function login(Email, Password) {
  try {
  const [rows] = await pool.query(`SELECT * FROM doctor WHERE Email = ?`, [Email]);
  if (!rows[0]) {
  return { error: 'Email is not registered' };
  }
  const match = await bcrypt.compare(Password, rows[0].Password);
  if (match) {
  const doctorId = rows[0].DoctorId;
   await pool.query(`UPDATE doctor SET IsActive = 1 WHERE DoctorId = ?`, [doctorId]);
  const { FirstName, Email, DoctorId } = rows[0];
  // create and return JWT
  return { token: jwt.sign({ FirstName, Email, DoctorId }, secret) };
  } else {
  return { error: 'Incorrect password' };
  }
} catch (err) {
  console.log(err);
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

