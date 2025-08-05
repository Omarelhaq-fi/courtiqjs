// hash-password.js
// This is a utility script to generate a hashed password from the command line.

const bcrypt = require('bcrypt');
const saltRounds = 10; // A standard value for the "cost" of hashing

// Get the password from command line arguments
const myPlaintextPassword = process.argv[2];

if (!myPlaintextPassword) {
    console.log('Usage: node hash-password.js <your_password_here>');
    process.exit(1);
}

console.log(`Hashing password: ${myPlaintextPassword}`);

bcrypt.hash(myPlaintextPassword, saltRounds, function(err, hash) {
    if (err) {
        console.error('Error hashing password:', err);
        return;
    }
    console.log('Hashed Password:');
    console.log(hash);
    console.log('\nCopy this hash and use it to update the password in your database.');
});
