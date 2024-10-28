/** @type {import('tailwindcss').Config} */
    module.exports = {
      content: {
        relative: true,
        files: ["*.html", "./src/**/*.rs"],
      },
      theme: {
        extend: {
          colors: {
            "pale-blue": "#3387b5",
            "pale-pink": "#c983c5"
          },
          fontFamily: {
            serif: ["Libre Baskerville", "serif"]          ,
            sans: ["Libre Franklin", "sans-serif"]
          }
        },
      },
      plugins: [],
    }
    
