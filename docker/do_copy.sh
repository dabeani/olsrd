#!/bin/bash

# Eingabe der IP-Adresse und des Benutzernamens
echo "Bitte geben Sie die IP-Adresse des Ziels ein:"
read ip_address
echo "Bitte geben Sie den Benutzernamen für die Verbindung ein:"
read username

# Zielpfad auswählen
echo "Bitte wählen Sie den Zielpfad aus:"
options=("/usb1-part1/" "/nvme1/" "/")
select target_path in "${options[@]}"; do
    if [ -n "$target_path" ]; then
        echo "Gewählter Zielpfad: $target_path"
        break
    else
        echo "Ungültige Auswahl. Bitte erneut versuchen."
    fi
done

# Dateien auflisten
files=(*.tar)

if [ ${#files[@]} -eq 0 ]; then
    echo "Keine .tar-Dateien gefunden!"
    exit 1
fi

echo "Bitte wählen Sie eine Datei aus:"
select file in "${files[@]}"; do
    if [ -n "$file" ]; then
        echo "Sie haben '$file' gewählt."
        scp "$file" "$username@$ip_address:$target_path$(basename "$file")"
        echo "Datei erfolgreich übertragen nach $target_path!"
        break
    else
        echo "Ungültige Auswahl. Bitte erneut versuchen."
    fi
done
