// ================= SMS SCAN =================
function scanSMS(){
     
    let message = document.getElementById("sms").value;

    if(message.trim() === ""){
        alert("Enter SMS first!");
        return;
    }

    fetch("/scan_sms", {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify({ message: message })
    })
    .then(res => res.json())
    .then(data => {

        let color = data.color || "black";

        let icon = "⚠️";
        if (data.result.includes("Safe")) icon = "✅";
        if (data.result.includes("Danger")) icon = "❌";

        document.getElementById("smsResult").innerHTML = `
        <div style="
            border:2px solid ${color};
            padding:20px;
            border-radius:12px;
            background:#fff;
            box-shadow:0 0 15px rgba(0,0,0,0.1);
            margin-top:20px;
        ">
            <h2 style="color:${color}">
                ${icon} ${data.result}
            </h2>

            <p><b>Risk Score:</b> ${data.risk_score}</p>

            <p><b>Reasons:</b></p>
            <ul>
                ${data.reasons.map(r => `<li>${r}</li>`).join("")}
            </ul>
        </div>
        `;
    })
    .catch(err => {
        console.log(err);
        alert("SMS scan error");
    });
}




// ================= APK SCAN =================

function scanAPK(){

    let fileInput = document.getElementById("apkFile");

    if(fileInput.files.length === 0){
        alert("Select APK first!");
        return;
    }

    let formData = new FormData();
    formData.append("apk", fileInput.files[0]);

    fetch("/scan_apk", {
        method: "POST",
        body: formData
    })
    .then(res => res.json())
    .then(data => {

        let color = data.color || "black";

        let icon = "⚠️";
        if (data.result.includes("Safe")) {
            icon = "✅";
        } else if (data.result.includes("Danger")) {
            icon = "❌";
        }

        document.getElementById("apkResult").innerHTML = `
        <div style="
            border:2px solid ${color};
            padding:20px;
            border-radius:12px;
            background:#fff;
            box-shadow:0 0 15px rgba(0,0,0,0.1);
            margin-top:20px;
        ">
     
        <div class="result-box ${data.result.includes('Safe') ? 'safe' : data.result.includes('Suspicious') ? 'suspicious' : 'danger'}">

        <h2>
            ${icon} ${data.result}
        </h2>
            

            <p><b>Risk Score:</b> ${data.risk_score}</p>

            <p><b>Reasons:</b></p>
            <ul>
                ${data.reasons.map(r => `<li>${r}</li>`).join("")}
            </ul>
        </div>
        `;
    })
    .catch(err => {
        console.log(err);
        alert("APK scan error");
    });
}

function verifySender(){

    let sender = document.getElementById("senderInput").value;

    fetch("/verify_sender",{
        method:"POST",
        headers:{
            "Content-Type":"application/json"
        },
        body:JSON.stringify({ sender: sender })
    })
    .then(res=>res.json())
    .then(data => {
    let resultText = document.getElementById("senderResult");
    resultText.innerHTML = "✔️ TEST WORKING";

    if (data.verdict.includes("Trusted")) {
        resultText.innerHTML = "✔️ " + data.verdict;
        resultText.style.color = "green";
    } else {
        resultText.innerHTML = "❌ " + data.verdict;
        resultText.style.color = "red";
    }
})
.catch(err => {
    console.log(err);
    alert("Verify error");
});
}
