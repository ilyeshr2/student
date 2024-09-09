document.getElementById('saveButton').addEventListener('click', function() {
    const studentName = document.getElementById('studentName').value;
    
    if (studentName) {
        // Store the student name in Chrome's local storage
        chrome.storage.local.set({ studentName: studentName }, function() {
            alert('Student name saved successfully!');
        });
    } else {
        alert('Please enter a valid name.');
    }
});
