import { aesGcmEncrypt, aesGcmDecrypt } from './crypto.js'
import { bufToHex, hexToBuf } from './bytes.js'

const SERVER_URL = import.meta.env.VITE_SERVER_URL || 'http://localhost:8787'

let semanticSearchAvailable = null

export function configureOpenAI() {
  return true
}

export async function extractTextContent(file) {
  const fileName = file.name.toLowerCase()
  const fileType = file.type.toLowerCase()
  
  try {
    if (fileType.startsWith('text/') || fileName.endsWith('.txt') || fileName.endsWith('.md') || fileName.endsWith('.csv')) {
      return await file.text()
    }
    
    if (fileType === 'application/json' || fileName.endsWith('.json')) {
      const text = await file.text()
      try {
        const json = JSON.parse(text)
        return JSON.stringify(json, null, 2)
      } catch {
        return text // If JSON parsing fails, return raw text
      }
    }
    
    if (fileName.endsWith('.js') || fileName.endsWith('.jsx') || fileName.endsWith('.ts') || fileName.endsWith('.tsx') || fileName.endsWith('.py') || fileName.endsWith('.html') || fileName.endsWith('.css')) {
      return await file.text()
    }
    
    return `filename: ${file.name} size: ${(file.size / 1024).toFixed(1)}KB type: ${file.type}`
    
  } catch (error) {
    console.warn('Failed to extract text from file:', error)
    return `filename: ${file.name} size: ${(file.size / 1024).toFixed(1)}KB type: ${file.type}`
  }
}

async function getOpenAIEmbedding(text) {
  const response = await fetch(`${SERVER_URL}/generate-embedding`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      text: text.substring(0, 8000)
    })
  })
  
  if (!response.ok) {
    const errorData = await response.json().catch(() => ({ error: 'Unknown error' }))
    throw new Error(`Server error: ${response.status} - ${errorData.error}`)
  }
  
  const data = await response.json()
  return data.embedding
}

export async function generateSemanticEmbedding(file, options = {}) {
  const { includeMetadata = true, maxTextLength = 8000 } = options
  
  const rawText = await extractTextContent(file)
  
  const parts = []
  
  if (includeMetadata) {
    parts.push(`Filename: ${file.name}`)
    parts.push(`File type: ${file.type}`)
    parts.push(`File size: ${(file.size / 1024).toFixed(1)}KB`)
  }
  
  parts.push(`Content: ${rawText}`)
  
  const fullText = parts.join('\n').substring(0, maxTextLength)
  
  try {
    const embedding = await getOpenAIEmbedding(fullText)
    
    return {
      embedding,
      textPreview: rawText.substring(0, 500),
      extractedLength: rawText.length,
      model: 'text-embedding-3-small',
      timestamp: Date.now(),
      metadata: {
        fileName: file.name,
        fileType: file.type,
        fileSize: file.size
      }
    }
  } catch (error) {
    console.error('Failed to generate embedding:', error)
    throw new Error(`Embedding generation failed: ${error.message}`)
  }
}

export async function encryptSemanticData(semanticData, key) {
  const jsonString = JSON.stringify(semanticData)
  const textEncoder = new TextEncoder()
  const data = textEncoder.encode(jsonString)
  
  const { iv, ciphertext } = await aesGcmEncrypt(key, data)
  
  return {
    encryptedEmbedding: bufToHex(ciphertext.buffer),
    embeddingIv: bufToHex(iv.buffer),
    model: semanticData.model,
    timestamp: semanticData.timestamp
  }
}

export async function decryptSemanticData(encryptedEmbedding, embeddingIv, key) {
  const ciphertext = new Uint8Array(hexToBuf(encryptedEmbedding))
  const iv = new Uint8Array(hexToBuf(embeddingIv))
  
  const decrypted = await aesGcmDecrypt(key, iv, ciphertext)
  const textDecoder = new TextDecoder()
  const jsonString = textDecoder.decode(decrypted)
  
  return JSON.parse(jsonString)
}

export function cosineSimilarity(embedding1, embedding2) {
  if (embedding1.length !== embedding2.length) {
    throw new Error('Embeddings must have same dimensions')
  }
  
  let dotProduct = 0
  let norm1 = 0
  let norm2 = 0
  
  for (let i = 0; i < embedding1.length; i++) {
    dotProduct += embedding1[i] * embedding2[i]
    norm1 += embedding1[i] * embedding1[i]
    norm2 += embedding2[i] * embedding2[i]
  }
  
  if (norm1 === 0 || norm2 === 0) return 0
  
  return dotProduct / (Math.sqrt(norm1) * Math.sqrt(norm2))
}

export async function searchSimilarFiles(queryText, manifestHistory, key, threshold = 0.7) {
  if (!manifestHistory.length) return []
  
  try {
    const queryEmbedding = await getOpenAIEmbedding(queryText)
    
    const results = []
    
    for (const manifest of manifestHistory) {
      if (manifest.semanticData) {
        try {
          const semanticData = await decryptSemanticData(
            manifest.semanticData.encryptedEmbedding,
            manifest.semanticData.embeddingIv,
            key
          )
          
          const similarity = cosineSimilarity(queryEmbedding, semanticData.embedding)
          
          if (similarity >= threshold) {
            results.push({
              manifest,
              similarity: Math.round(similarity * 100) / 100,
              textPreview: semanticData.textPreview,
              metadata: semanticData.metadata,
              matchScore: similarity
            })
          }
        } catch (error) {
          console.warn(`Failed to search manifest ${manifest.fileName}:`, error)
        }
      }
    }
    
    return results.sort((a, b) => b.similarity - a.similarity)
    
  } catch (error) {
    console.error('Semantic search failed:', error)
    throw new Error(`Search failed: ${error.message}`)
  }
}

export async function advancedSearch(query, manifestHistory, key, options = {}) {
  const {
    semanticThreshold = 0.6,
    maxResults = 10,
    includeKeywordSearch = true,
    includeMetadataSearch = true,
    weights = {
      semantic: 0.7,
      keyword: 0.2,
      metadata: 0.1
    }
  } = options
  
  if (!manifestHistory.length) return []
  
  const results = new Map()
  const queryLower = query.toLowerCase()
  const queryWords = queryLower.split(/\s+/).filter(word => word.length > 2)
  
  try {
    try {
      const semanticResults = await searchSimilarFiles(query, manifestHistory, key, semanticThreshold)
      
      semanticResults.forEach(result => {
        const id = result.manifest.id
        const existing = results.get(id) || { manifest: result.manifest, totalScore: 0, matchTypes: [] }
        
        existing.totalScore += result.similarity * weights.semantic
        existing.matchTypes.push({
          type: 'semantic',
          score: result.similarity,
          details: `${(result.similarity * 100).toFixed(1)}% semantic similarity`
        })
        existing.textPreview = result.textPreview
        
        results.set(id, existing)
      })
    } catch (error) {
      console.warn('Semantic search failed, continuing with keyword search:', error.message)
    }
    
    if (includeKeywordSearch) {
      for (const manifest of manifestHistory) {
        const id = manifest.id
        let keywordScore = 0
        const matchDetails = []
        
        if (manifest.fileName.toLowerCase().includes(queryLower)) {
          keywordScore += 0.8
          matchDetails.push('exact filename match')
        } else {
          const filenameMatches = queryWords.filter(word => 
            manifest.fileName.toLowerCase().includes(word)
          ).length
          if (filenameMatches > 0) {
            keywordScore += (filenameMatches / queryWords.length) * 0.6
            matchDetails.push(`${filenameMatches}/${queryWords.length} filename keywords`)
          }
        }
        
        if (manifest.semanticData) {
          try {
            const semanticData = await decryptSemanticData(
              manifest.semanticData.encryptedEmbedding,
              manifest.semanticData.embeddingIv,
              key
            )
            
            const contentLower = semanticData.textPreview.toLowerCase()
            if (contentLower.includes(queryLower)) {
              keywordScore += 0.4
              matchDetails.push('exact content match')
            } else {
              const contentMatches = queryWords.filter(word => 
                contentLower.includes(word)
              ).length
              if (contentMatches > 0) {
                keywordScore += (contentMatches / queryWords.length) * 0.3
                matchDetails.push(`${contentMatches}/${queryWords.length} content keywords`)
              }
            }
          } catch (error) {
            console.warn(`Failed to search content for ${manifest.fileName}:`, error)
          }
        }
        
        if (keywordScore > 0) {
          const existing = results.get(id) || { manifest, totalScore: 0, matchTypes: [] }
          existing.totalScore += keywordScore * weights.keyword
          existing.matchTypes.push({
            type: 'keyword',
            score: keywordScore,
            details: matchDetails.join(', ')
          })
          results.set(id, existing)
        }
      }
    }
    
    if (includeMetadataSearch) {
      for (const manifest of manifestHistory) {
        const id = manifest.id
        let metadataScore = 0
        const matchDetails = []
        
        if (manifest.fileName.toLowerCase().includes(queryLower)) {
          const ext = manifest.fileName.split('.').pop()?.toLowerCase()
          if (ext && queryLower.includes(ext)) {
            metadataScore += 0.3
            matchDetails.push(`file type: ${ext}`)
          }
        }
        
        if (manifest.timestamp) {
          const fileDate = new Date(manifest.timestamp)
          const now = new Date()
          const daysDiff = Math.floor((now - fileDate) / (1000 * 60 * 60 * 24))
          
          if ((queryLower.includes('today') || queryLower.includes('recent')) && daysDiff === 0) {
            metadataScore += 0.2
            matchDetails.push('uploaded today')
          } else if (queryLower.includes('yesterday') && daysDiff === 1) {
            metadataScore += 0.2
            matchDetails.push('uploaded yesterday')
          } else if (queryLower.includes('week') && daysDiff <= 7) {
            metadataScore += 0.1
            matchDetails.push('uploaded this week')
          }
        }
        
        if (metadataScore > 0) {
          const existing = results.get(id) || { manifest, totalScore: 0, matchTypes: [] }
          existing.totalScore += metadataScore * weights.metadata
          existing.matchTypes.push({
            type: 'metadata',
            score: metadataScore,
            details: matchDetails.join(', ')
          })
          results.set(id, existing)
        }
      }
    }
    
    return Array.from(results.values())
      .filter(result => result.totalScore > 0.1)
      .sort((a, b) => b.totalScore - a.totalScore)
      .slice(0, maxResults)
      .map(result => ({
        ...result,
        totalScore: Math.round(result.totalScore * 100) / 100,
        relevanceLevel: result.totalScore > 0.8 ? 'high' : result.totalScore > 0.4 ? 'medium' : 'low'
      }))
    
  } catch (error) {
    console.error('Advanced search failed:', error)
    throw new Error(`Search failed: ${error.message}`)
  }
}

export async function isSemanticSearchAvailable() {
  if (semanticSearchAvailable !== null) return semanticSearchAvailable
  
  try {
    const response = await fetch(`${SERVER_URL}/health`)
    if (response.ok) {
      const testResponse = await fetch(`${SERVER_URL}/generate-embedding`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ text: 'test' })
      })
      semanticSearchAvailable = testResponse.ok || testResponse.status !== 500
    } else {
      semanticSearchAvailable = false
    }
  } catch {
    semanticSearchAvailable = false
  }
  
  return semanticSearchAvailable
}

export async function getSearchSuggestions(manifestHistory, key, limit = 5) {
  if (!manifestHistory.length) return []
  
  const suggestions = []
  const fileTypes = new Set()
  const commonWords = new Map()
  
  for (const manifest of manifestHistory.slice(0, 20)) {
    const ext = manifest.fileName.split('.').pop()?.toLowerCase()
    if (ext) fileTypes.add(ext)
    
    const words = manifest.fileName.toLowerCase()
      .replace(/[^\w\s]/g, ' ')
      .split(/\s+/)
      .filter(word => word.length > 3)
    
    words.forEach(word => {
      commonWords.set(word, (commonWords.get(word) || 0) + 1)
    })
    
    if (manifest.semanticData) {
      try {
        const semanticData = await decryptSemanticData(
          manifest.semanticData.encryptedEmbedding,
          manifest.semanticData.embeddingIv,
          key
        )
        
        const contentWords = semanticData.textPreview.toLowerCase()
          .replace(/[^\w\s]/g, ' ')
          .split(/\s+/)
          .filter(word => word.length > 4)
          .slice(0, 10)
        
        contentWords.forEach(word => {
          commonWords.set(word, (commonWords.get(word) || 0) + 1)
        })
      } catch (error) {
      }
    }
  }
  
  Array.from(fileTypes).slice(0, 3).forEach(type => {
    suggestions.push({
      text: `${type} files`,
      type: 'filetype',
      icon: 'file'
    })
  })
  
  const topWords = Array.from(commonWords.entries())
    .sort(([,a], [,b]) => b - a)
    .slice(0, limit - suggestions.length)
  
  topWords.forEach(([word, count]) => {
    if (count > 1) {
      suggestions.push({
        text: word,
        type: 'keyword',
        icon: 'search',
        count
      })
    }
  })
  
  return suggestions.slice(0, limit)
}