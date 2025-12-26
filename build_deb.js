/*
 * OWL - Connection Manager
 * Copyright (C) 2025 Mohamed AZGHARI
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

const installer = require('electron-installer-debian');

const options = {
    src: 'dist/OWL-linux-x64/',
    dest: 'dist/installers/',
    arch: 'amd64',
    icon: 'owl_logo.png',
    name: 'owl',
    productName: 'OWL Connection Manager',
    genericName: 'Connection Manager',
    version: '1.0.0',
    description: 'A simple connection manager',
    categories: ['Network'],
    maintainer: 'Mazghari <mohamed.azghari99@gmail.com>', // Placeholder, required field
    homepage: 'https://github.com/mazghari/owl', // Placeholder
    bin: 'OWL', // Name of the binary in the src folder
    scripts: {
        postrm: 'debian_postrm.sh'
    }
};

console.log('Creating package (this may take a while)...');

installer(options)
    .then(data => console.log(`Successfully created package at ${data.packagePaths}`))
    .catch(err => {
        console.error(err, err.stack);
        process.exit(1);
    });
