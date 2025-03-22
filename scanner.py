grep "Exec" ~/.config/xfce4/terminal/terminalrc ~/.config/gnome-terminal/ ~/.bashrc ~/.profile ~/.zshrc 2>/dev/null

cat /etc/sudoers | grep -i "Defaults root"

sudo rm -rf /etc/systemd/system/getty@tty1.service.d/autologin.conf
sudo rm -rf /etc/gdm3/custom.conf
sudo rm -rf /etc/lightdm/lightdm.conf
sudo rm -rf /etc/sddm.conf
sudo systemctl daemon-reload

2024-03-06T06:17:27,469940+00:00
