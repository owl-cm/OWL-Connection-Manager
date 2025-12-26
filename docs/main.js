// Initialize Lucide icons
document.addEventListener('DOMContentLoaded', () => {
    if (window.lucide) {
        window.lucide.createIcons();
    }

    // Scroll Reveal Animation
    const observerOptions = {
        threshold: 0.1
    };

    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.style.opacity = '1';
                entry.target.style.transform = 'translateY(0)';
            }
        });
    }, observerOptions);

    // Apply reveal effect to sections and cards
    const revealElements = document.querySelectorAll('.feature-card, .section-header, .security-content, .security-visual');
    revealElements.forEach(el => {
        el.style.opacity = '0';
        el.style.transform = 'translateY(30px)';
        el.style.transition = 'all 0.8s cubic-bezier(0.4, 0, 0.2, 1)';
        observer.observe(el);
    });

    // Smooth scrolling for nav links
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function (e) {
            e.preventDefault();
            const target = document.querySelector(this.getAttribute('href'));
            if (target) {
                target.scrollIntoView({
                    behavior: 'smooth'
                });
            }
        });
    });

    // Navbar background change on scroll
    const nav = document.querySelector('nav');
    window.addEventListener('scroll', () => {
        if (window.scrollY > 50) {
            nav.style.background = 'rgba(10, 10, 12, 0.95)';
            nav.style.padding = '1rem 10%';
        } else {
            nav.style.background = 'rgba(10, 10, 12, 0.8)';
            nav.style.padding = '2rem 10%';
        }
    });

    // GitHub Releases Integration
    const REPO = 'owl-cm/OWL-Connection-Manager';
    const versionSelect = document.getElementById('version-select');
    const heroDownloadBtn = document.getElementById('hero-download-btn');
    const navDownloadBtn = document.getElementById('nav-download-btn');

    async function fetchReleases() {
        try {
            const response = await fetch(`https://api.github.com/repos/${REPO}/releases`);
            const releases = await response.json();

            if (!Array.isArray(releases) || releases.length === 0) {
                versionSelect.innerHTML = '<option value="">No releases found</option>';
                return;
            }

            versionSelect.innerHTML = '';

            // Filter releases that have a .deb asset
            const validReleases = releases.filter(release =>
                release.assets.some(asset => asset.name.endsWith('.deb'))
            );

            if (validReleases.length === 0) {
                versionSelect.innerHTML = '<option value="">No .deb found</option>';
                return;
            }

            validReleases.forEach((release, index) => {
                const option = document.createElement('option');
                option.value = release.tag_name;
                option.textContent = release.tag_name + (index === 0 ? ' (Latest)' : '');

                // Find the .deb asset
                const debAsset = release.assets.find(asset => asset.name.endsWith('.deb'));
                option.dataset.downloadUrl = debAsset.browser_download_url;

                versionSelect.appendChild(option);
            });

            // Set initial download link
            updateDownloadLinks();

        } catch (error) {
            console.error('Error fetching releases:', error);
            versionSelect.innerHTML = '<option value="">Error loading</option>';
        }
    }

    function updateDownloadLinks() {
        const selectedOption = versionSelect.options[versionSelect.selectedIndex];
        if (selectedOption && selectedOption.dataset.downloadUrl) {
            const url = selectedOption.dataset.downloadUrl;
            heroDownloadBtn.href = url;
            navDownloadBtn.href = url;
        }
    }

    versionSelect.addEventListener('change', updateDownloadLinks);

    // Initial fetch
    fetchReleases();
});
