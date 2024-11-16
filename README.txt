User Groups

# create a group
sudo groupadd rustuser

# add it as a secondary group for your user
sudo usermod -aG docker $USER

// sudo visudo add
rustuser  ALL=(ALL:ALL) ALL

# Change user
passwd rustuser


With Compressors

Flate2:


8 * Core Proc
12th Gen Intel® Core™ i3-1215U × 8