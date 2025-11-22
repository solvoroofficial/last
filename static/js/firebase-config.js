// Firebase web config (provided by user)
const firebaseConfig = {
  apiKey: "AIzaSyAZFREHO-9DYrtDU2IsdoV3ip_kQNOU9uE",
  authDomain: "prabha-graphics.firebaseapp.com",
  projectId: "prabha-graphics",
  storageBucket: "prabha-graphics.firebasestorage.app",
  messagingSenderId: "501116062940",
  appId: "1:501116062940:web:e42f9a7a132d204e26f819",
  measurementId: "G-56VQCKCF47"
};

// Initialize Firebase client SDK when needed.
// Example usage (in other client scripts):
// import { initializeApp } from 'https://www.gstatic.com/firebasejs/9.22.2/firebase-app.js';
// const app = initializeApp(firebaseConfig);

window.__FIREBASE_CLIENT_CONFIG__ = firebaseConfig;
