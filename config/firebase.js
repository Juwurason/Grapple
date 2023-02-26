import { initializeApp } from "firebase/app";
import { getStorage, ref } from 'firebase/storage'

const firebaseConfig = {
  apiKey: "AIzaSyCSgbl8bj5FDIpCRBovBQd1nDLWgJgsmDw",
  authDomain: "grapple-a4d53.firebaseapp.com",
  projectId: "grapple-a4d53",
  storageBucket: "grapple-a4d53.appspot.com",
  messagingSenderId: "1044421142459",
  appId: "1:1044421142459:web:dc47d8563e49f6d47dc69e",
  measurementId: "G-ZFWKMMZ2ND"
};
const app = initializeApp(firebaseConfig);


// const store = getStorage(app);

// const bucketRef = ref(store, process.env.Bucket_url);
// export default bucketRef;

// const app = initializeApp(firebaseConfig);
const Storage = getStorage(app);

export default Storage ;