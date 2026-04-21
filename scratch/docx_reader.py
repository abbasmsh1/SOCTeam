import sys
import zipfile
import xml.etree.ElementTree as ET

def docx_to_text(path):
    """Simple docx to text extractor using zipfile/xml."""
    try:
        with zipfile.ZipFile(path) as z:
            xml_content = z.read('word/document.xml')
        
        tree = ET.fromstring(xml_content)
        namespace = {'w': 'http://schemas.openxmlformats.org/wordprocessingml/2006/main'}
        
        text = []
        for paragraph in tree.findall('.//w:p', namespace):
            texts = paragraph.findall('.//w:t', namespace)
            if texts:
                text.append("".join([t.text for t in texts if t.text is not None]))
        
        return "\n".join(text)
    except Exception as e:
        return f"Error: {e}"

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python docx_reader.py <file_path> <output_path>")
    else:
        text = docx_to_text(sys.argv[1])
        with open(sys.argv[2], 'w', encoding='utf-8') as f:
            f.write(text)
        print(f"Text extracted to {sys.argv[2]}")
