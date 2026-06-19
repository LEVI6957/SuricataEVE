<!DOCTYPE html>
<html>
<head><title>Upload Image</title></head>
<body>
    <h2>Upload your image (VULNERABLE)</h2>
    <form action="upload.php" method="post" enctype="multipart/form-data">
        Select image to upload:
        <input type="file" name="fileToUpload" id="fileToUpload">
        <input type="submit" value="Upload Image" name="submit">
    </form>

    <?php
    if(isset($_POST["submit"])) {
        $target_dir = "uploads/";
        if (!file_exists($target_dir)) {
            mkdir($target_dir, 0777, true);
        }
        $target_file = $target_dir . basename($_FILES["fileToUpload"]["name"]);
        
        // VULNERABILITY: No extension checking! Any file can be uploaded.
        if (move_uploaded_file($_FILES["fileToUpload"]["tmp_name"], $target_file)) {
            echo "<p style='color:green;'>The file ". htmlspecialchars( basename( $_FILES["fileToUpload"]["name"])). " has been uploaded.</p>";
            echo "<p>Access your file here: <a href='$target_file'>$target_file</a></p>";
        } else {
            echo "<p style='color:red;'>Sorry, there was an error uploading your file.</p>";
        }
    }
    ?>
</body>
</html>
