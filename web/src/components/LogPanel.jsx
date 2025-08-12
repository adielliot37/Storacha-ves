import React, { useEffect, useRef } from 'react'

export default function LogPanel({ lines }) {
  const ref = useRef(null)
  useEffect(() => {
    if (ref.current) ref.current.scrollTop = ref.current.scrollHeight
  }, [lines])
  return (
    <div ref={ref} className="log">
      {lines.map((ln, i) => (
        <div key={i}>
          <span className="t">[{ln.time}]</span>{" "}
          <span className={ln.level}>{ln.text}</span>
        </div>
      ))}
    </div>
  )
}