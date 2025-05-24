
// LogFlow Main JavaScript

document.addEventListener('DOMContentLoaded', function() {
    // Tab switching
    const tabBtns = document.querySelectorAll('.tab-btn');
    
    tabBtns.forEach(btn => {
        btn.addEventListener('click', function() {
            const tabId = this.getAttribute('data-tab');
            
            // Remove active class from all tabs and contents
            document.querySelectorAll('.tab-btn').forEach(tab => {
                tab.classList.remove('active');
            });
            
            document.querySelectorAll('.tab-content').forEach(content => {
                content.classList.remove('active');
            });
            
            // Add active class to clicked tab and corresponding content
            this.classList.add('active');
            document.getElementById(tabId).classList.add('active');
        });
    });
    
    // Copy API Key
    const copyApiKeyBtn = document.getElementById('copy-api-key');
    if (copyApiKeyBtn) {
        copyApiKeyBtn.addEventListener('click', function() {
            const apiKey = document.getElementById('api-key').textContent;
            navigator.clipboard.writeText(apiKey).then(() => {
                // Show a temporary tooltip or change the button text
                const originalHTML = this.innerHTML;
                this.innerHTML = '<i class="fas fa-check"></i>';
                setTimeout(() => {
                    this.innerHTML = originalHTML;
                }, 2000);
            });
        });
    }
    
    // Copy code examples
    const copyCodeBtns = document.querySelectorAll('.copy-code-btn');
    copyCodeBtns.forEach(btn => {
        btn.addEventListener('click', function() {
            const codeBlock = this.previousElementSibling;
            const code = codeBlock.textContent;
            
            navigator.clipboard.writeText(code).then(() => {
                const originalHTML = this.innerHTML;
                this.innerHTML = '<i class="fas fa-check"></i> Copied!';
                setTimeout(() => {
                    this.innerHTML = originalHTML;
                }, 2000);
            });
        });
    });
    
    // Toggle log details
    const logDetailsBtns = document.querySelectorAll('.log-details-btn');
    logDetailsBtns.forEach(btn => {
        btn.addEventListener('click', function() {
            const logRow = this.closest('.log-row');
            const detailsRow = logRow.nextElementSibling;
            
            if (detailsRow.style.display === 'none' || !detailsRow.style.display) {
                detailsRow.style.display = 'table-row';
                this.innerHTML = '<i class="fas fa-eye-slash"></i>';
                this.title = 'Hide Details';
            } else {
                detailsRow.style.display = 'none';
                this.innerHTML = '<i class="fas fa-eye"></i>';
                this.title = 'View Details';
            }
        });
    });
    
    // Filter logs by level
    const levelFilter = document.getElementById('level-filter');
    if (levelFilter) {
        levelFilter.addEventListener('change', function() {
            const level = this.value.toUpperCase();
            const logRows = document.querySelectorAll('.log-row');
            
            logRows.forEach(row => {
                if (!level || row.getAttribute('data-level') === level) {
                    row.style.display = 'table-row';
                } else {
                    row.style.display = 'none';
                    // Also hide details row if it's open
                    const detailsRow = row.nextElementSibling;
                    if (detailsRow && detailsRow.classList.contains('log-details-row')) {
                        detailsRow.style.display = 'none';
                    }
                }
            });
        });
    }
    
    // Show example modal
    const showExampleBtn = document.getElementById('show-example-modal');
    const exampleModal = document.getElementById('example-modal');
    const modalClose = document.querySelector('.modal-close');
    
    if (showExampleBtn && exampleModal) {
        showExampleBtn.addEventListener('click', function() {
            exampleModal.classList.add('show');
        });
        
        modalClose.addEventListener('click', function() {
            exampleModal.classList.remove('show');
        });
        
        // Close modal when clicking outside
        window.addEventListener('click', function(event) {
            if (event.target === exampleModal) {
                exampleModal.classList.remove('show');
            }
        });
    }
    
    // Mobile sidebar toggle
    const sidebarToggle = document.querySelector('.sidebar-toggle');
    const sidebar = document.querySelector('.sidebar');
    
    if (sidebarToggle && sidebar) {
        sidebarToggle.addEventListener('click', function() {
            sidebar.classList.toggle('active');
        });
    }
    
    // Password strength meter
    const passwordInput = document.getElementById('password');
    const strengthMeter = document.querySelector('.strength-meter');
    const strengthText = document.querySelector('.strength-text');
    
    if (passwordInput && strengthMeter && strengthText) {
        passwordInput.addEventListener('input', function() {
            const value = this.value;
            let strength = 0;
            
            if (value.length >= 8) strength += 1;
            if (value.match(/[a-z]/) && value.match(/[A-Z]/)) strength += 1;
            if (value.match(/\d/)) strength += 1;
            if (value.match(/[^a-zA-Z\d]/)) strength += 1;
            
            switch(strength) {
                case 0:
                    strengthMeter.style.width = '0%';
                    strengthMeter.style.backgroundColor = '';
                    strengthText.textContent = 'Password strength';
                    break;
                case 1:
                    strengthMeter.style.width = '25%';
                    strengthMeter.style.backgroundColor = 'var(--red)';
                    strengthText.textContent = 'Weak';
                    break;
                case 2:
                    strengthMeter.style.width = '50%';
                    strengthMeter.style.backgroundColor = 'var(--orange)';
                    strengthText.textContent = 'Fair';
                    break;
                case 3:
                    strengthMeter.style.width = '75%';
                    strengthMeter.style.backgroundColor = 'var(--yellow)';
                    strengthText.textContent = 'Good';
                    break;
                case 4:
                    strengthMeter.style.width = '100%';
                    strengthMeter.style.backgroundColor = 'var(--green)';
                    strengthText.textContent = 'Strong';
                    break;
            }
        });
    }
});
