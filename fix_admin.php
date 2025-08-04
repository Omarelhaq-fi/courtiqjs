<?php
// fix_admin.php
require_once 'db_connect.php';

// --- IMPORTANT SECURITY NOTE ---
// This file should be deleted immediately after you use it once.

$admin_username = 'Omarelhaq';
$new_password = 'omarreda123';

// Create a new, secure hash that Node.js (bcrypt) can understand
$new_password_hash = password_hash($new_password, PASSWORD_BCRYPT, ['cost' => 10]);

// Update the admin user in the database with the new, compatible hash
$stmt = $conn->prepare("UPDATE users SET password_hash = ? WHERE username = ?");
$stmt->bind_param("ss", $new_password_hash, $admin_username);

if ($stmt->execute()) {
    echo "<h1>SUCCESS!</h1>";
    echo "<p>The admin password for '{$admin_username}' has been securely updated.</p>";
    echo "<p style='color:red; font-weight:bold;'>You should now DELETE this file (fix_admin.php) from your server immediately.</p>";
} else {
    echo "<h1>ERROR!</h1>";
    echo "<p>Could not update the password. Please check your database connection and table names.</p>";
}

$stmt->close();
$conn->close();
?>
