// this code is for the nav bar
function openNav() {
  document.getElementById("myNav").style.width = "100%";
}

function closeNav() {
  document.getElementById("myNav").style.width = "0%";
}

// code for truncation in index.html
function showMore(id) {
   var truncateReviews = document.getElementById(id+"_truncated"); 
  var fullReviews = document.getElementById(id+"_full");
  var show = document.getElementById(id+"_show");
document.getElementById(id+"_show");
 if (truncateReviews.style.display =="block") {
   fullReviews.style.display = "block";
   truncateReviews.style.display = "none";
   show.innerText = "Show Less";
   
    
 } else{
   truncateReviews.style.display ="block"; 
   fullReviews.style.display ="none";
   show.innerText = "show More";
 
 }

 }

