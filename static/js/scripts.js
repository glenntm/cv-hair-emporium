
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


// Get the modal element (with proper null checks)
var modalElement = document.getElementById('exampleModalCenter');
var myModal = null;

if (modalElement) {
  myModal = new bootstrap.Modal(modalElement, {
    keyboard: false  // Prevents closing with the ESC key (optional)
  });
}

// Get the open modal button and attach event listener
var openModalBtn = document.getElementById('openModalBtn');
if (openModalBtn && myModal) {
  openModalBtn.addEventListener('click', function () {
    myModal.show(); // Opens the modal
  });

  //Close modal
  var closeModalBtn = document.getElementById('closeModalBtn');
  if (closeModalBtn) {
    closeModalBtn.addEventListener('click', function () {
      myModal.hide(); // Closes the modal
    });
  }
}

// Close modal X button handler (with null check)
var closeModalX = document.getElementById('closeModalX');
if (closeModalX && myModal) {
  closeModalX.addEventListener('click', function () {
    myModal.hide(); // Closes the modal
  });
}


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
  
  
  // Custom Dropbox Gallery
  function loadCustomGallery() {
    console.log('loadCustomGallery called');
    const loadingSpinner = document.getElementById('loading-spinner');
    const galleryGrid = document.getElementById('gallery-grid');
    const galleryError = document.getElementById('gallery-error');
    
    // Show loading spinner
    loadingSpinner.style.display = 'block';
    galleryGrid.innerHTML = '';
    galleryError.style.display = 'none';
    
    console.log('Fetching from /api/gallery-images/1/20');
    // Fetch images from Flask API with pagination (20 images per page)
    fetch('/api/gallery-images/1/20')
      .then(response => {
        console.log('Got response:', response);
        return response.json();
      })
      .then(data => {
        loadingSpinner.style.display = 'none';
        
        if (data.error) {
          console.error('Gallery API error:', data.error);
          galleryError.style.display = 'block';
          return;
        }
        
        if (!data.images || data.images.length === 0) {
          galleryGrid.innerHTML = '<p style="text-align: center; color: #666; padding: 2rem;">No images found in gallery.</p>';
          return;
        }
        
        // Pagination is handled by backend - don't slice client-side
        // Just display all images returned and show "Load More" if has_next is true
        
        console.log(`Total images returned from API: ${data.images.length}`);
        console.log(`Pagination info:`, data.pagination);
        
        // Show all images returned (all 20)
        data.images.forEach(image => {
          const galleryItem = document.createElement('div');
          galleryItem.className = 'gallery-item';
          
          galleryItem.innerHTML = `
            <img src="${image.url}" alt="${image.name}" loading="lazy" style="opacity: 0; transition: opacity 0.3s ease;">
            <div class="image-overlay">
              <p class="image-name">${image.name}</p>
            </div>
          `;
          
          // Add fade-in effect when image loads
          const img = galleryItem.querySelector('img');
          img.onload = function() {
            this.style.opacity = '1';
          };
          img.onerror = function() {
            this.style.opacity = '0';
            this.parentNode.innerHTML = '<p style="color: #e74c3c; padding: 2rem;">Failed to load image</p>';
          };
          
          // Add click to open full size
          galleryItem.addEventListener('click', function() {
            const fullImageUrl = image.full_url || image.url;
            window.open(fullImageUrl, '_blank');
          });
          
          galleryGrid.appendChild(galleryItem);
        });
        
        // Show Load More button if there are more pages
        if (data.pagination && data.pagination.has_next) {
          const loadMoreBtn = document.createElement('button');
          loadMoreBtn.className = 'cs-button-solid cs-button1';
          loadMoreBtn.textContent = `Load More`;
          loadMoreBtn.style.cssText = 'display: block; margin: 2rem auto;';
          
          let currentPage = data.pagination.page;
          
          loadMoreBtn.addEventListener('click', function() {
            currentPage++;
            console.log(`Loading page ${currentPage}...`);
            
            // Fetch next page
            fetch(`/api/gallery-images/${currentPage}/20`)
              .then(response => response.json())
              .then(nextData => {
                // Append new images
                nextData.images.forEach(image => {
                  const galleryItem = document.createElement('div');
                  galleryItem.className = 'gallery-item';
                  
                  galleryItem.innerHTML = `
                    <img src="${image.url}" alt="${image.name}" loading="lazy" style="opacity: 0; transition: opacity 0.3s ease;">
                    <div class="image-overlay">
                      <p class="image-name">${image.name}</p>
                    </div>
                  `;
                  
                  const img = galleryItem.querySelector('img');
                  img.onload = function() {
                    this.style.opacity = '1';
                  };
                  
                  galleryItem.addEventListener('click', function() {
                    window.open(image.url, '_blank');
                  });
                  
                  galleryGrid.appendChild(galleryItem);
                });
                
                // Update or remove button
                if (nextData.pagination && nextData.pagination.has_next) {
                  loadMoreBtn.textContent = `Load More`;
                } else {
                  loadMoreBtn.remove();
                }
              })
              .catch(error => {
                console.error('Error loading more images:', error);
              });
          });
          
          galleryGrid.parentNode.appendChild(loadMoreBtn);
        }
        
        console.log(`Loaded ${data.images.length} images into gallery`);
      })
      .catch(error => {
        console.error('Error loading gallery:', error);
        loadingSpinner.style.display = 'none';
        galleryError.style.display = 'block';
      });
  }
  
  // Initialize gallery when page loads
  document.addEventListener('DOMContentLoaded', function() {
    console.log('DOM loaded, checking for gallery-grid...');
    const galleryGrid = document.getElementById('gallery-grid');
    console.log('Gallery grid element:', galleryGrid);
    // Only load gallery if we're on the gallery page
    if (galleryGrid) {
      console.log('Loading custom gallery...');
      loadCustomGallery();
    } else {
      console.log('Gallery grid not found, not on gallery page');
    }
  });


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




