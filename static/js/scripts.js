
// Nav Bar 
function toggleMenu(){
    const menu = document.querySelector(".menu-links");
    const icon = document.querySelector(".hamburger-icon");
    menu.classList.toggle("open");
    icon.classList.toggle("open");
}

// add classes for mobile navigation toggling
var CSbody = document.querySelector("body");
const CSnavbarMenu = document.querySelector("#cs-navigation");
const CShamburgerMenu = document.querySelector("#cs-navigation .cs-toggle");

CShamburgerMenu.addEventListener('click', function() {
    CShamburgerMenu.classList.toggle("cs-active");
    CSnavbarMenu.classList.toggle("cs-active");
    CSbody.classList.toggle("cs-open");
    // run the function to check the aria-expanded value
    ariaExpanded();
});

// checks the value of aria expanded on the cs-ul and changes it accordingly whether it is expanded or not 
function ariaExpanded() {
    const csUL = document.querySelector('#cs-expanded');
    const csExpanded = csUL.getAttribute('aria-expanded');

    if (csExpanded === 'false') {
        csUL.setAttribute('aria-expanded', 'true');
    } else {
        csUL.setAttribute('aria-expanded', 'false');
    }
}

// This script adds a class to the body after scrolling 100px
// and we used these body.scroll styles to create some on scroll 
// animations with the navbar

document.addEventListener('scroll', (e) => { 
    const scroll = document.documentElement.scrollTop;
    if(scroll >= 100){
document.querySelector('body').classList.add('scroll')
    } else {
    document.querySelector('body').classList.remove('scroll')
    }
});

// mobile nav toggle code
const dropDowns = Array.from(document.querySelectorAll('#cs-navigation .cs-dropdown'));
    for (const item of dropDowns) {
        const onClick = () => {
        item.classList.toggle('cs-active')
    }
    item.addEventListener('click', onClick)
    }


// Get the modal element
var myModal = new bootstrap.Modal(document.getElementById('exampleModalCenter'), {
  keyboard: false  // Prevents closing with the ESC key (optional)
});

// Get the open modal button and attach event listener
document.getElementById('openModalBtn').addEventListener('click', function () {
  myModal.show(); // Opens the modal
});

//Close modal
document.getElementById('closeModalBtn').addEventListener('click', function () {
  myModal.hide(); // Closes the modal
});

document.getElementById('closeModalX').addEventListener('click', function () {
  myModal.hide(); // Closes the modal
});


//Carousel Code
document.addEventListener("DOMContentLoaded", function() {
  var myCarousel = document.querySelector('#carouselExampleControls');
  var carousel = new bootstrap.Carousel(myCarousel, {
      interval: 2000,
      ride: 'carousel'
  });

  // Optional custom buttons
  var prevButton = document.querySelector('.carousel-control-prev');
  var nextButton = document.querySelector('.carousel-control-next');

  prevButton.addEventListener('click', function () {
      carousel.prev();
  });

  nextButton.addEventListener('click', function () {
      carousel.next();
  });
});

//function for services tab
function openSection(evt, sectionName) {
    // Hide all section content
    const sectionContents = document.querySelectorAll('.section-content');
    sectionContents.forEach(content => content.classList.remove('active'));

    // Remove active class from all section links
    const sectionLinks = document.querySelectorAll('.section-link');
    sectionLinks.forEach(link => link.classList.remove('active'));

    // Show the current section and add the active class to the clicked section link
    document.getElementById(sectionName).classList.add('active');
    evt.currentTarget.classList.add('active');
}



//function for google SSO
function onSuccess(googleUser) {
    console.log('Logged in as: ' + googleUser.getBasicProfile().getName());
  }
  function onFailure(error) {
    console.log(error);
  }
  function renderButton() {
    gapi.signin2.render('my-signin2', {
      'scope': 'profile email',
      'width': 240,
      'height': 50,
      'longtitle': true,
      'theme': 'dark',
      'onsuccess': onSuccess,
      'onfailure': onFailure
    });
  }
  
  
  //display dropbox content
  var options = {
    // Shared link to Dropbox file
    link: "https://www.dropbox.com/scl/fo/w67ugqfuvjgrjn5e7wtl5/AAiHMRNQrko0IovsAB9MndM?rlkey=gfnnr93l09cuzw8uia95ip3ee&st=axyakoku&dl=0",
    file: {
      // Sets the zoom mode for embedded files. Defaults to 'best'.
      zoom: "best" // best or "fit"
    },
    folder: {
      // Sets the view mode for embedded folders. Defaults to 'list'.
      view: "grid",
      headerSize: "normal" // or "small"
    }
  }
  Dropbox.embed(options, element);


  //Password requirements
  const passwordInput = document.getElementById('password-1525');
  const passwordPattern = /^(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;

  passwordInput.addEventListener('input', function() {
    if (passwordPattern.test(passwordInput.value)) {
      passwordInput.setCustomValidity('');
      passwordInput.style.borderColor = 'green';
    } else {
      passwordInput.setCustomValidity('Password must be at least 8 characters, include at least one uppercase letter, one number, and one special character.');
      passwordInput.style.borderColor = 'red';
    }
  });

  //Star ratings
  document.querySelectorAll('.stars input').forEach((input) => {
    input.addEventListener('change', (event) => {
        const selectedRating = event.target.value;
        console.log(`Selected Rating: ${selectedRating}`);
    });
});

function toggleSubSection(event) {
    event.stopPropagation();
    const li = event.currentTarget;
    const subSection = li.querySelector('.sub-section');
    const arrow = li.querySelector('.arrow');

    if (li.classList.contains('active')) {
        li.classList.remove('active');
        subSection.style.maxHeight = '0';
    } else {
        li.classList.add('active');
        subSection.style.maxHeight = subSection.scrollHeight + 'px';
    }
}

function toggleSubSection(event) {
  event.stopPropagation();
  const li = event.currentTarget;
  const subSection = li.querySelector('.sub-section');
  const arrow = li.querySelector('.arrow');

  if (li.classList.contains('active')) {
      li.classList.remove('active');
      subSection.style.maxHeight = '0';
  } else {
      li.classList.add('active');
      subSection.style.maxHeight = subSection.scrollHeight + 'px';
  }
}

function toggleInnerSubSection(event) {
  event.stopPropagation();
  const p = event.currentTarget;
  const innerSubSection = p.nextElementSibling;

  if (p.classList.contains('active')) {
      p.classList.remove('active');
      innerSubSection.style.maxHeight = '0';
  } else {
      p.classList.add('active');
      innerSubSection.style.maxHeight = innerSubSection.scrollHeight + 'px';
  }
}




