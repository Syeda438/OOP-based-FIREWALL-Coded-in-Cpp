
import { GoogleGenAI, Type } from "@google/genai";
import { Rule } from "../types";

export const analyzeSecurity = async (rules: Rule[]) => {
  const ai = new GoogleGenAI({ apiKey: process.env.API_KEY });
  
  const rulesJson = JSON.stringify(rules, null, 2);
  const prompt = `As a world-class senior network security architect, perform a deep audit of this C++ OOP firewall rule set. 
  The rules are evaluated in the order provided (index-based priority).
  Analyze for:
  1. Rule shadowing (rules that will never be reached because a broader rule precedes them).
  2. Security holes in the 3-zone model (Inside, Partial, Outside).
  3. Optimization of the evaluation chain.
  
  Rules to analyze: 
  ${rulesJson}`;

  try {
    const response = await ai.models.generateContent({
      model: "gemini-3-pro-preview",
      contents: prompt,
      config: {
        thinkingConfig: { thinkingBudget: 32768 },
        responseMimeType: "application/json",
        responseSchema: {
          type: Type.OBJECT,
          properties: {
            summary: { type: Type.STRING },
            riskLevel: { type: Type.STRING, description: "CRITICAL, HIGH, MEDIUM, or LOW" },
            findings: {
              type: Type.ARRAY,
              items: {
                type: Type.OBJECT,
                properties: {
                  description: { type: Type.STRING },
                  recommendation: { type: Type.STRING }
                },
                required: ["description", "recommendation"]
              }
            }
          },
          required: ["summary", "riskLevel", "findings"]
        },
      },
    });

    return JSON.parse(response.text || '{}');
  } catch (error) {
    console.error("Gemini Audit Error:", error);
    return {
      summary: "Failed to perform deep AI audit.",
      riskLevel: "UNKNOWN",
      findings: []
    };
  }
};

export const searchGroundingConsultant = async (query: string) => {
  const ai = new GoogleGenAI({ apiKey: process.env.API_KEY });
  
  try {
    const response = await ai.models.generateContent({
      model: "gemini-3-flash-preview",
      contents: `You are a cybersecurity consultant with real-time access to the web. 
      Answer the following technical question about firewall implementation, C++ networking, or multi-machine security strategy.
      Provide concrete commands or architecture advice where possible.
      Question: ${query}`,
      config: {
        tools: [{ googleSearch: {} }],
      },
    });

    const sources = response.candidates?.[0]?.groundingMetadata?.groundingChunks || [];
    return {
      text: response.text,
      sources: sources
    };
  } catch (error) {
    console.error("Consultant Error:", error);
    return { text: "I'm sorry, I couldn't reach my intelligence database right now.", sources: [] };
  }
};
