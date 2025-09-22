'use client';

import { useEffect, useRef } from 'react';

interface ChartData {
  labels: string[];
  values: number[];
  colors?: string[];
}

interface SimpleChartProps {
  data: ChartData;
  type: 'bar' | 'line' | 'doughnut';
  title?: string;
}

export default function SimpleChart({ data, type, title }: SimpleChartProps) {
  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    // Clear canvas
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    
    const { labels, values, colors = ['#3B82F6', '#8B5CF6', '#10B981', '#F59E0B', '#EF4444'] } = data;
    
    if (type === 'doughnut') {
      drawDoughnutChart(ctx, canvas, values, labels, colors);
    } else if (type === 'bar') {
      drawBarChart(ctx, canvas, values, labels, colors);
    } else if (type === 'line') {
      drawLineChart(ctx, canvas, values, labels, colors);
    }
  }, [data, type]);

  const drawDoughnutChart = (ctx: CanvasRenderingContext2D, canvas: HTMLCanvasElement, values: number[], labels: string[], colors: string[]) => {
    const centerX = canvas.width / 2;
    const centerY = canvas.height / 2;
    const radius = Math.min(centerX, centerY) - 20;
    const innerRadius = radius * 0.6;

    const total = values.reduce((sum, val) => sum + val, 0);
    let currentAngle = -Math.PI / 2;

    values.forEach((value, index) => {
      const sliceAngle = (value / total) * 2 * Math.PI;
      
      // Draw outer arc
      ctx.beginPath();
      ctx.arc(centerX, centerY, radius, currentAngle, currentAngle + sliceAngle);
      ctx.arc(centerX, centerY, innerRadius, currentAngle + sliceAngle, currentAngle, true);
      ctx.closePath();
      ctx.fillStyle = colors[index % colors.length];
      ctx.fill();

      currentAngle += sliceAngle;
    });

    // Draw center text
    ctx.fillStyle = '#FFFFFF';
    ctx.font = 'bold 16px sans-serif';
    ctx.textAlign = 'center';
    ctx.fillText(total.toString(), centerX, centerY);
  };

  const drawBarChart = (ctx: CanvasRenderingContext2D, canvas: HTMLCanvasElement, values: number[], labels: string[], colors: string[]) => {
    const padding = 40;
    const chartWidth = canvas.width - padding * 2;
    const chartHeight = canvas.height - padding * 2;
    const barWidth = chartWidth / values.length * 0.6;
    const maxValue = Math.max(...values);

    values.forEach((value, index) => {
      const barHeight = (value / maxValue) * chartHeight;
      const x = padding + (chartWidth / values.length) * index + (chartWidth / values.length - barWidth) / 2;
      const y = canvas.height - padding - barHeight;

      // Draw bar
      ctx.fillStyle = colors[index % colors.length];
      ctx.fillRect(x, y, barWidth, barHeight);

      // Draw value on top
      ctx.fillStyle = '#FFFFFF';
      ctx.font = '12px sans-serif';
      ctx.textAlign = 'center';
      ctx.fillText(value.toString(), x + barWidth / 2, y - 5);
    });
  };

  const drawLineChart = (ctx: CanvasRenderingContext2D, canvas: HTMLCanvasElement, values: number[], labels: string[], colors: string[]) => {
    const padding = 40;
    const chartWidth = canvas.width - padding * 2;
    const chartHeight = canvas.height - padding * 2;
    const maxValue = Math.max(...values);

    // Draw line
    ctx.beginPath();
    ctx.strokeStyle = colors[0];
    ctx.lineWidth = 3;

    values.forEach((value, index) => {
      const x = padding + (chartWidth / (values.length - 1)) * index;
      const y = canvas.height - padding - (value / maxValue) * chartHeight;

      if (index === 0) {
        ctx.moveTo(x, y);
      } else {
        ctx.lineTo(x, y);
      }

      // Draw points
      ctx.fillStyle = colors[0];
      ctx.beginPath();
      ctx.arc(x, y, 4, 0, 2 * Math.PI);
      ctx.fill();
    });

    ctx.stroke();
  };

  return (
    <div className="bg-white/10 backdrop-blur-xl rounded-xl p-4 border border-white/20">
      {title && (
        <h3 className="text-white font-medium mb-3 text-center">{title}</h3>
      )}
      <canvas
        ref={canvasRef}
        width={300}
        height={200}
        className="w-full h-auto"
      />
    </div>
  );
}