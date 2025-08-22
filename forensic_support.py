#!/usr/bin/env python3
"""
Forensic Support Module for WBEM Parser
Handles forensic images, mounted drives, and various input scenarios.
"""

import os
import sys
import subprocess
import tempfile
import shutil
from pathlib import Path


class ForensicHandler:
    """Handle various forensic input types for WBEM parsing."""
    
    def __init__(self):
        self.temp_mount_dir = None
        self.cleanup_required = False
        
    def __enter__(self):
        return self
        
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.cleanup()
    
    def detect_input_type(self, input_path):
        """Detect the type of input provided."""
        if not os.path.exists(input_path):
            return 'nonexistent'
        
        if os.path.isdir(input_path):
            # Check if it looks like a Windows directory structure
            if self._is_windows_directory(input_path):
                return 'windows_directory'
            return 'directory'
        
        if os.path.isfile(input_path):
            # Check file extension and magic bytes
            file_ext = Path(input_path).suffix.lower()
            
            if file_ext in ['.dd', '.img', '.raw', '.001']:
                return 'forensic_image'
            elif file_ext in ['.e01', '.ex01']:
                return 'encase_image'
            elif file_ext in ['.vmdk', '.vhd', '.vhdx']:
                return 'virtual_disk'
            elif file_ext in ['.iso']:
                return 'iso_image'
            else:
                # Check magic bytes
                return self._detect_by_magic_bytes(input_path)
        
        return 'unknown'
    
    def prepare_input(self, input_path):
        """Prepare input for parsing, handling different forensic formats."""
        input_type = self.detect_input_type(input_path)
        
        if input_type == 'nonexistent':
            raise FileNotFoundError(f"Input path does not exist: {input_path}")
        
        if input_type == 'windows_directory':
            # Direct access to Windows directory
            return self._find_wbem_repository(input_path)
        
        if input_type == 'directory':
            # Search for WBEM repository in directory structure
            return self._find_wbem_repository(input_path)
        
        if input_type in ['forensic_image', 'encase_image', 'virtual_disk', 'iso_image']:
            # Mount the image and find WBEM repository
            return self._mount_and_find_repository(input_path, input_type)
        
        # If unknown, try to treat as directory
        return self._find_wbem_repository(input_path)
    
    def _is_windows_directory(self, path):
        """Check if directory looks like a Windows system."""
        windows_indicators = [
            'Windows',
            'Program Files',
            'System32',
            'wbem'
        ]
        
        # Check for Windows-like structure
        for root, dirs, files in os.walk(path):
            for indicator in windows_indicators:
                if indicator in dirs or indicator.lower() in [d.lower() for d in dirs]:
                    return True
            # Don't recurse too deep
            if root.count(os.sep) - path.count(os.sep) > 3:
                break
        
        return False
    
    def _detect_by_magic_bytes(self, file_path):
        """Detect file type by examining magic bytes."""
        try:
            with open(file_path, 'rb') as f:
                magic_bytes = f.read(512)
            
            # Common forensic image signatures
            if magic_bytes.startswith(b'EVF\x09\x0d\x0a\xff\x00'):  # EnCase E01
                return 'encase_image'
            elif magic_bytes[510:512] == b'\x55\xaa':  # MBR signature
                return 'forensic_image'
            elif b'KDMV' in magic_bytes[:100]:  # VMDK
                return 'virtual_disk'
            elif magic_bytes.startswith(b'conectix'):  # VHD
                return 'virtual_disk'
            
        except Exception:
            pass
        
        return 'unknown'
    
    def _find_wbem_repository(self, base_path):
        """Find WBEM repository in a directory structure."""
        search_paths = [
            'Windows/System32/wbem/Repository',
            'WINDOWS/System32/wbem/Repository',
            'windows/system32/wbem/repository',
            'System32/wbem/Repository',
            'system32/wbem/repository',
            'wbem/Repository',
            'wbem/repository',
            'Repository',
            'repository'
        ]
        
        # Search for repository directory
        for search_path in search_paths:
            full_path = os.path.join(base_path, search_path)
            if os.path.exists(full_path):
                # Verify it contains repository files
                if self._verify_repository_directory(full_path):
                    return full_path
        
        # If not found in standard locations, search recursively
        return self._recursive_repository_search(base_path)
    
    def _verify_repository_directory(self, path):
        """Verify that a directory contains WBEM repository files."""
        required_files = ['INDEX.BTR', 'OBJECTS.DATA']
        
        for root, dirs, files in os.walk(path):
            files_upper = [f.upper() for f in files]
            for required_file in required_files:
                if required_file in files_upper:
                    return True
        
        return False
    
    def _recursive_repository_search(self, base_path):
        """Recursively search for repository files."""
        target_files = ['INDEX.BTR', 'OBJECTS.DATA', 'index.btr', 'objects.data']
        
        for root, dirs, files in os.walk(base_path):
            for target_file in target_files:
                if target_file in files:
                    # Found a repository file, return the directory
                    return root
            
            # Don't go too deep
            if root.count(os.sep) - base_path.count(os.sep) > 10:
                continue
        
        # If no repository files found, return the base path
        return base_path
    
    def _mount_and_find_repository(self, image_path, image_type):
        """Mount a forensic image and find the WBEM repository."""
        print(f"Detected {image_type}, attempting to mount...")
        
        # Create temporary mount directory
        self.temp_mount_dir = tempfile.mkdtemp(prefix='wbem_forensic_')
        self.cleanup_required = True
        
        try:
            if image_type == 'forensic_image':
                self._mount_raw_image(image_path)
            elif image_type == 'encase_image':
                self._mount_encase_image(image_path)
            elif image_type == 'virtual_disk':
                self._mount_virtual_disk(image_path)
            elif image_type == 'iso_image':
                self._mount_iso_image(image_path)
            
            # Find repository in mounted image
            return self._find_wbem_repository(self.temp_mount_dir)
            
        except Exception as e:
            print(f"Failed to mount {image_type}: {str(e)}")
            print("Trying to process as raw directory...")
            return image_path
    
    def _mount_raw_image(self, image_path):
        """Mount a raw forensic image using loop device."""
        try:
            # Try to mount directly
            cmd = ['sudo', 'mount', '-o', 'ro,loop', image_path, self.temp_mount_dir]
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode != 0:
                # Try with offset detection
                print("Direct mount failed, trying with offset detection...")
                self._mount_with_offset_detection(image_path)
                
        except Exception as e:
            raise Exception(f"Failed to mount raw image: {str(e)}")
    
    def _mount_with_offset_detection(self, image_path):
        """Mount with automatic offset detection."""
        try:
            # Use fdisk to find partition offset
            cmd = ['fdisk', '-l', image_path]
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                for line in lines:
                    if 'NTFS' in line or 'Windows' in line:
                        parts = line.split()
                        if len(parts) >= 2:
                            start_sector = int(parts[1])
                            offset = start_sector * 512
                            
                            cmd = ['sudo', 'mount', '-o', f'ro,loop,offset={offset}', 
                                   image_path, self.temp_mount_dir]
                            result = subprocess.run(cmd, capture_output=True, text=True)
                            
                            if result.returncode == 0:
                                return
            
            raise Exception("Could not determine partition offset")
            
        except Exception as e:
            raise Exception(f"Offset detection failed: {str(e)}")
    
    def _mount_encase_image(self, image_path):
        """Mount an EnCase E01 image."""
        try:
            # Check if ewfmount is available
            if shutil.which('ewfmount'):
                cmd = ['ewfmount', image_path, self.temp_mount_dir]
                result = subprocess.run(cmd, capture_output=True, text=True)
                
                if result.returncode == 0:
                    # Now mount the ewf1 file
                    ewf_file = os.path.join(self.temp_mount_dir, 'ewf1')
                    if os.path.exists(ewf_file):
                        mount_dir = tempfile.mkdtemp(prefix='wbem_ewf_')
                        cmd = ['sudo', 'mount', '-o', 'ro,loop', ewf_file, mount_dir]
                        result = subprocess.run(cmd, capture_output=True, text=True)
                        
                        if result.returncode == 0:
                            self.temp_mount_dir = mount_dir
                            return
            
            print("ewfmount not available, treating as raw image...")
            self._mount_raw_image(image_path)
            
        except Exception as e:
            raise Exception(f"Failed to mount EnCase image: {str(e)}")
    
    def _mount_virtual_disk(self, image_path):
        """Mount a virtual disk image."""
        try:
            # Try qemu-nbd for VMDK/VHD
            if shutil.which('qemu-nbd'):
                # This requires root privileges and nbd module
                print("Virtual disk mounting requires manual setup with qemu-nbd")
                print(f"Run: sudo qemu-nbd -r -c /dev/nbd0 {image_path}")
                print("Then: sudo mount -o ro /dev/nbd0p1 /mnt/point")
            
            # Fallback to treating as regular file
            raise Exception("Virtual disk mounting not fully automated")
            
        except Exception as e:
            raise Exception(f"Failed to mount virtual disk: {str(e)}")
    
    def _mount_iso_image(self, image_path):
        """Mount an ISO image."""
        try:
            cmd = ['sudo', 'mount', '-o', 'ro,loop', image_path, self.temp_mount_dir]
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode != 0:
                raise Exception(f"Mount failed: {result.stderr}")
                
        except Exception as e:
            raise Exception(f"Failed to mount ISO: {str(e)}")
    
    def cleanup(self):
        """Clean up temporary mount points."""
        if self.cleanup_required and self.temp_mount_dir:
            try:
                # Unmount if mounted
                cmd = ['sudo', 'umount', self.temp_mount_dir]
                subprocess.run(cmd, capture_output=True)
                
                # Remove temporary directory
                if os.path.exists(self.temp_mount_dir):
                    os.rmdir(self.temp_mount_dir)
                    
            except Exception as e:
                print(f"Warning: Failed to cleanup mount point: {str(e)}")
            
            self.cleanup_required = False
            self.temp_mount_dir = None
    
    def get_alternative_paths(self, base_path):
        """Get alternative paths to try if primary path fails."""
        alternatives = []
        
        # Add common Windows path variations
        windows_paths = [
            'Windows/System32/wbem',
            'WINDOWS/System32/wbem', 
            'windows/system32/wbem',
            'System32/wbem',
            'system32/wbem'
        ]
        
        for win_path in windows_paths:
            alt_path = os.path.join(base_path, win_path)
            if os.path.exists(alt_path):
                alternatives.append(alt_path)
        
        return alternatives


def enhanced_repository_finder(input_path):
    """Enhanced repository finder with forensic support."""
    with ForensicHandler() as handler:
        try:
            repository_path = handler.prepare_input(input_path)
            return repository_path
        except Exception as e:
            print(f"Forensic handler failed: {str(e)}")
            # Fallback to basic directory search
            return input_path


if __name__ == "__main__":
    """Test the forensic handler."""
    if len(sys.argv) < 2:
        print("Usage: python forensic_support.py <input_path>")
        sys.exit(1)
    
    input_path = sys.argv[1]
    
    with ForensicHandler() as handler:
        input_type = handler.detect_input_type(input_path)
        print(f"Detected input type: {input_type}")
        
        try:
            repository_path = handler.prepare_input(input_path)
            print(f"Repository path: {repository_path}")
        except Exception as e:
            print(f"Error: {str(e)}")