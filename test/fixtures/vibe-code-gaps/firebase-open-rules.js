// Firebase config with open rules
const firebaseConfig = {
  apiKey: "AIzaSyD1234567890abcdefghijklmnopqrstuv",
  authDomain: "myapp.firebaseapp.com",
  databaseURL: "https://myapp-default-rtdb.firebaseio.com",
};

const rules = {
  ".read": true,
  ".write": true,
};