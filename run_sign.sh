#!/bin/bash
cd /mnt/c/Users/smolk/Documents/palera1n-windows/Dopamine_darksword
python3 sign_app.py \
  build_app/DarkSword.app \
  cert.pem \
  key.pem \
  "ios (2) (2).mobileprovision"
echo "EXIT=$?"
