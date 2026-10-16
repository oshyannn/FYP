chrome.tabs.query(
{
    active: true,
    currentWindow: true
},
function(tabs)
{
    const currentUrl = tabs[0].url;

    // show URL in popup
    document.getElementById("url").innerText = currentUrl;

    // send URL to backend
    fetch("http://127.0.0.1:5000/analyze", {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify({
            url: currentUrl
        })
    })
    .then(response => response.json())
    .then(data => {
        console.log(data);
    })
    .catch(error => {
        console.error(error);
    });
}
);